package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.dcql.DCQLEvaluator;
import io.github.wistefan.dcql.QueryResult;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.credential.CredentialBase;
import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.credentials.CredentialsRepository;
import io.github.wistefan.oid4vp.exception.*;
import io.github.wistefan.oid4vp.model.*;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.stream.Collectors;

import static io.github.wistefan.oid4vp.OIDConstants.*;

/**
 * OID4VP Client implementation to return an access-token after authenticating through the
 * OID4VP {@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html} Same-Device-Flow.
 */
@Slf4j
public class OID4VPClient {

    /**
     * Configuration to be used for the authorization process
     */
    private final HolderConfiguration holderConfiguration;
    private final ObjectMapper objectMapper;
    /**
     * Evaluator for DCQL Queries
     */
    private final DCQLEvaluator dcqlEvaluator;
    /**
     * Repository to provide access to the credentials
     */
    private final CredentialsRepository credentialsRepository;
    /**
     * Service to handle signing of the VerifiablePresentations.
     */
    private final SigningService signingService;
    /**
     * Client to interact with the OpenId-Configuration endpoint.
     */
    private final OpenIdConfigurationClient openIdConfigurationClient;
    /**
     * Client to interact with the authorization endpoints.
     */
    private final AuthorizationClient authorizationClient;

    private final CryptoUtils cryptoUtils;

    public OID4VPClient(HttpClient httpClient, HolderConfiguration holderConfiguration, ObjectMapper objectMapper, List<ClientResolver> clientResolvers, DCQLEvaluator dcqlEvaluator, CredentialsRepository credentialsRepository, SigningService signingService) {
        this(
                holderConfiguration,
                objectMapper,
                dcqlEvaluator,
                credentialsRepository,
                signingService,
                new OpenIdConfigurationClient(httpClient, objectMapper),
                new AuthorizationClient(httpClient, objectMapper, clientResolvers),
                CryptoUtils.getInstance());
    }

    public OID4VPClient(HolderConfiguration holderConfiguration, ObjectMapper objectMapper, DCQLEvaluator dcqlEvaluator, CredentialsRepository credentialsRepository, SigningService signingService, OpenIdConfigurationClient openIdConfigurationClient, AuthorizationClient authorizationClient, CryptoUtils cryptoUtils) {
        this.holderConfiguration = holderConfiguration;
        this.objectMapper = objectMapper;
        this.dcqlEvaluator = dcqlEvaluator;
        this.credentialsRepository = credentialsRepository;
        this.signingService = signingService;
        this.openIdConfigurationClient = openIdConfigurationClient;
        this.authorizationClient = authorizationClient;
        this.cryptoUtils = cryptoUtils;
    }

    /**
     * Return a {@link TokenResponse} according to the OAuth2 definition, following the OID4VP SameDevice-Flow:
     * 1. Get OpenID Configuration from the .well-known/openid-configuration
     * 2. Call authorizationEndpoint
     * 3. Follow authorizationEndpoint to retrieve the AuthorizationRequest
     * 4. Select credentials to be presented, based on the AuthorizationRequest
     * 5. Create VerifiablePresentation and encode as vp_token
     * 6. Post vp_token to verifier
     * 7. Return the TokenResponse
     */
    public CompletableFuture<TokenResponse> getAccessToken(RequestParameters requestParameters) {
        return openIdConfigurationClient.getOpenIdConfiguration(requestParameters)
                .thenCompose(openIdConfiguration -> callAuthorizationEndpoint(openIdConfiguration, requestParameters))
                .thenCompose(authorizationInformation -> authorize(authorizationInformation, requestParameters))
                .exceptionally(ex -> {
                    throw checkExceptions(ex);
                });
    }


    private RuntimeException checkExceptions(Throwable re) {
        // completion exceptions mask the original cause, thus we have to extract it.
        if (re instanceof CompletionException ce) {
            return checkExceptions(ce.getCause());
        }
        if (!(re instanceof AuthorizationException)
                && !(re instanceof AuthorizationRequestException)
                && !(re instanceof BadGatewayException)
                && !(re instanceof ClientResolutionException)
                && !(re instanceof CredentialsAccessException)) {
            log.warn("Received unexpected exception.", re);
            return new Oid4VPException("Unspecific exception was thrown.", re);

        }
        // already wrapped exceptions can just pass
        return (RuntimeException) re;
    }


    /**
     * Call the authorizationEndpoint as advertised in the OpenIdConfiguration and follow it to the AuthorizationRequest.
     */
    private CompletableFuture<AuthorizationInformation> callAuthorizationEndpoint(OpenIdConfiguration openIdConfiguration, RequestParameters requestParameters) {
        String state = cryptoUtils.generateRandomString(16);
        String nonce = cryptoUtils.generateRandomString(16);

        AuthorizationQuery authorizationQuery = new AuthorizationQuery(state,
                nonce,
                requestParameters.clientId(),
                requestParameters.scope(),
                RESPONSE_TYPE_CODE);
        try {
            URI authorizationURI = new URI(
                    openIdConfiguration.getAuthorizationEndpoint().getScheme(),
                    openIdConfiguration.getAuthorizationEndpoint().getAuthority(),
                    openIdConfiguration.getAuthorizationEndpoint().getPath(),
                    authorizationQuery.toString(),
                    openIdConfiguration.getAuthorizationEndpoint().getFragment()
            );

            return authorizationClient.sendAuthorizationRequest(authorizationURI)
                    .thenApply(authorizationRequest -> {
                        validateAuthorizationRequest(authorizationRequest, authorizationQuery);
                        return authorizationRequest;
                    })
                    .thenApply(authorizationRequest -> new AuthorizationInformation(openIdConfiguration, authorizationRequest));

        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Was not able to create the authorization uri.", e);
        }
    }

    private void validateAuthorizationRequest(AuthorizationRequest authorizationRequest, AuthorizationQuery authorizationQuery) {
        if (authorizationRequest.getNonce() == null || !authorizationRequest.getNonce().equals(authorizationQuery.nonce())) {
            throw new AuthorizationRequestException("Authorization request contains wrong nonce.");
        }
        if (authorizationRequest.getState() == null || !authorizationRequest.getState().equals(authorizationQuery.state())) {
            throw new AuthorizationRequestException("Authorization request contains wrong state.");
        }
        if (authorizationRequest.getResponseType() == null || !authorizationRequest.getResponseType().equals(RESPONSE_TYPE_VP_TOKEN)) {
            throw new AuthorizationRequestException(String.format("Authorization request asks for response_type %s. Only %s is currently supported.", authorizationRequest.getResponseType(), RESPONSE_TYPE_VP_TOKEN));
        }
        if (authorizationRequest.getResponseMode() == null || !authorizationRequest.getResponseMode().equals(RESPONSE_MODE_DIRECT_POST)) {
            throw new AuthorizationRequestException(String.format("Authorization request asks for response_mode %s. Only %s is currently supported.", authorizationRequest.getResponseMode(), RESPONSE_MODE_DIRECT_POST));
        }
    }

    /**
     * Use the {@link  AuthorizationInformation} to request a token at the verifier.
     */
    private CompletableFuture<TokenResponse> authorize(AuthorizationInformation authorizationInformation, RequestParameters requestParameters) {
        String authorizationResponseString = buildAuthorizationResponse(authorizationInformation.authorizationRequest());
        String formData = AuthorizationFormResponse.builder()
                .scopes(requestParameters.scope())
                .vpToken(authorizationResponseString)
                .clientId(requestParameters.clientId())
                .build().getAsFormBody();

        return authorizationClient.sendAuthorizationResponse(authorizationInformation.openIdConfiguration().getTokenEndpoint(), formData);
    }


    /**
     * Build the vp_token, based on the {@link AuthorizationRequest}. Will evaluate potential
     * DCQL-Queries{@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html#name-digital-credentials-query-l}
     * and use the resulting credentials.
     */
    private String buildAuthorizationResponse(AuthorizationRequest authorizationRequest) {
        if (authorizationRequest.getDcqlQuery() != null) {
            QueryResult queryResult = dcqlEvaluator.evaluateDCQLQuery(authorizationRequest.getDcqlQuery(), credentialsRepository.getCredentials());
            if (!queryResult.success()) {
                throw new AuthorizationException(String.format("The requested credentials are not available. DCQL was: %s.", authorizationRequest.getDcqlQuery()));
            }
            // in case of set credentials, we need to create a vp_token per set and put them in an object, keyed by the purpose
            if (DCQLEvaluator.containsCredentialSets(authorizationRequest.getDcqlQuery())) {
                Map<Object, String> vpMap = queryResult.credentials()
                        .entrySet()
                        .stream()
                        .map(entry -> Map.entry(entry.getKey(), buildVP(entry.getValue())))
                        .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue, (e1, e2) -> e1));
                try {
                    return Base64.getUrlEncoder().encodeToString(objectMapper.writeValueAsBytes(vpMap));
                } catch (JsonProcessingException e) {
                    throw new AuthorizationException("Was not able to encode the authorization response object.", e);
                }
            } else {
                List<List<Credential>> credentialsLists = new ArrayList<>(queryResult.credentials().values());
                if (credentialsLists.size() != 1) {
                    log.debug("Illegal DCQL Result - DCQL: {} - Returned: {}", authorizationRequest.getDcqlQuery(), queryResult);
                    throw new AuthorizationException("DCQL Query evaluation delivered an illegal result.");
                }
                return buildVP(credentialsLists.getFirst());
            }
        } else {
            // send all that we can get.
            return buildVP(credentialsRepository.getCredentials());
        }
    }

    /**
     * Create a signed vp_token of the credentials list.
     */
    private String buildVP(List<Credential> credentials) {

        VerifiablePresentation verifiablePresentation = new VerifiablePresentation();
        verifiablePresentation.setHolder(holderConfiguration.holderId());
        verifiablePresentation.setVerifiableCredential(credentials.stream()
                .map(Credential::getRawCredential)
                .map(CredentialBase::getRaw)
                .map(Object.class::cast)
                .toList());

        return signingService.signPresentation(verifiablePresentation);
    }


    public static <T> HttpResponse.BodyHandler<T> asJson(ObjectMapper objectMapper, Class<T> targetType) {
        return responseInfo -> HttpResponse.BodySubscribers.mapping(
                HttpResponse.BodySubscribers.ofString(Charset.defaultCharset()),
                body -> {
                    try {
                        return objectMapper.readValue(body, targetType);
                    } catch (IOException e) {
                        throw new BadGatewayException("The body was not of the expected type.", e);
                    }
                }
        );
    }


}

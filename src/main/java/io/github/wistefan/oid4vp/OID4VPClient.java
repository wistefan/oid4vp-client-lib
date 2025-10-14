package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.dcql.DCQLEvaluator;
import io.github.wistefan.dcql.QueryResult;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.credential.CredentialBase;
import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.credentials.CredentialsRepository;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.exception.AuthorizationRequestException;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.*;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.Charset;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Collectors;

/**
 * OID4VP Client implementation to return an access-token after authenticating through the
 * OID4VP {@see https://openid.net/specs/openid-4-verifiable-presentations-1_0.html} Same-Device-Flow.
 */
@Slf4j
@RequiredArgsConstructor
public class OID4VPClient {


    private static final String OID_WELL_KNOWN = "/.well-known/openid-configuration";
    private static final String VP_TOKEN_GRANT_TYPE = "vp_token";
    private static final String CODE_RESPONSE_TYPE = "code";
    private static final String LOCATION_HEADER = "Location";
    private static final String OPENID_4_VP_SCHEME = "openid4vp";

    /**
     * HttpClient to be used, it should support normal-redirecting
     */
    private final HttpClient httpClient;
    /**
     * Configuration to be used for the authorization process
     */
    private final HolderConfiguration holderConfiguration;
    private final ObjectMapper objectMapper;
    /**
     * Client Resolvers to be used
     */
    private final List<ClientResolver> clientResolvers;
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
        return getOpenIdConfiguration(requestParameters)
                .thenCompose(openIdConfiguration -> callAuthorizationEndpoint(openIdConfiguration, requestParameters))
                .thenCompose(authorizationInformation -> authorize(authorizationInformation, requestParameters));
    }

    /**
     * Retrieve OpenID-Configuration from the configured endpoint
     */
    private CompletableFuture<OpenIdConfiguration> getOpenIdConfiguration(RequestParameters requestParameters) {
        URI wellKnownAddress = requestParameters
                .host()
                .resolve(requestParameters.path())
                .resolve(OID_WELL_KNOWN);
        HttpRequest wellKnownRequest = HttpRequest.newBuilder(wellKnownAddress).GET().build();

        return httpClient.sendAsync(wellKnownRequest, asJson(objectMapper, OpenIdConfiguration.class))
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return response.body(); // success path
                    }
                    throw new BadGatewayException(
                            String.format("Was not able to retrieve OpenId Configuration from %s - status: %s",
                                    wellKnownAddress,
                                    response.statusCode()
                            ));
                });
    }

    /**
     * Call the authorizationEndpoint as advertised in the OpenIdConfiguration and follow it to the AuthorizationRequest.
     */
    private CompletableFuture<AuthorizationInformation> callAuthorizationEndpoint(OpenIdConfiguration openIdConfiguration, RequestParameters requestParameters) {
        validateOpenIDConfiguration(openIdConfiguration, requestParameters);
        String state = CryptoUtils.generateRandomString(16);
        String nonce = CryptoUtils.generateRandomString(16);

        AuthorizationQuery authorizationQuery = new AuthorizationQuery(state,
                nonce,
                requestParameters.clientId(),
                requestParameters.scope(),
                CODE_RESPONSE_TYPE);
        try {
            URI authorizationURI = new URI(
                    openIdConfiguration.getAuthorizationEndpoint().getScheme(),
                    openIdConfiguration.getAuthorizationEndpoint().getAuthority(),
                    openIdConfiguration.getAuthorizationEndpoint().getPath(),
                    authorizationQuery.toString(),
                    openIdConfiguration.getAuthorizationEndpoint().getFragment()
            );

            HttpRequest authorizationRequest = HttpRequest.newBuilder(authorizationURI).GET().build();
            return httpClient.sendAsync(authorizationRequest, HttpResponse.BodyHandlers.ofString())
                    .thenCompose(response -> {
                        if (response.statusCode() == 302) {
                            return handleAuthorizationRedirectResponse(response);
                        } else {
                            throw new BadGatewayException(
                                    String.format("Was not able to get authorization response from %s - status: %s",
                                            openIdConfiguration.getAuthorizationEndpoint(),
                                            response.statusCode()
                                    ));
                        }
                    })
                    .thenApply(ar -> new AuthorizationInformation(openIdConfiguration, ar));

        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Was not able to create the authorization uri.", e);
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
        HttpRequest authorizationResponse = HttpRequest
                .newBuilder(authorizationInformation.openIdConfiguration().getTokenEndpoint())
                .header("Content-Type", "application/x-www-form-urlencoded")
                .POST(HttpRequest.BodyPublishers.ofString(formData))
                .build();
        return httpClient.sendAsync(authorizationResponse, asJson(objectMapper, TokenResponse.class))
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return response.body();
                    }
                    throw new AuthorizationException(String.format("Did not receive a successfully token response. Was: %s", response.statusCode()));
                });
    }

    /**
     * Handle redirects from the authorizationEndpoint towards OpendId4VP Deeplinks.
     */
    private CompletableFuture<AuthorizationRequest> handleAuthorizationRedirectResponse(HttpResponse<?> httpResponse) {
        if (httpResponse.statusCode() != 302) {
            throw new IllegalArgumentException("The given response was not a redirect.");
        }
        URI location = httpResponse.headers()
                .firstValue(LOCATION_HEADER)
                .map(URI::create)
                .orElseThrow(() -> new IllegalArgumentException("The redirect response does not contain a location header."));

        if (!location.getScheme().equals(OPENID_4_VP_SCHEME)) {
            throw new IllegalArgumentException(String.format("The location is not redirecting to an openid4vp uri. Was: %s", location));
        }
        OpenId4VPQuery openId4VPQuery = OpenId4VPQuery.fromQueryString(location.getQuery());
        return getAuthorizationRequest(openId4VPQuery);
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


    /**
     * Handles the JWT providing the AuthorizationRequest
     * 1. Resolve the client, according to its scheme, to a public key
     * 2. Verify the JWT
     * 3. Decode it to the AuthorizationRequest
     */
    private CompletableFuture<AuthorizationRequest> handleAuthorizationRequestJWT(OpenId4VPQuery query, String jwt) {
        try {
            SignedJWT parsedJwt = SignedJWT.parse(jwt);
            return clientResolvers.stream()
                    .filter(cr -> cr.isSupportedId(query.getClientId()))
                    .findFirst()
                    .orElseThrow(() -> new ClientResolutionException(String.format("The provided clientId %s is not supported.", query.getClientId())))
                    .getPublicKey(query.getClientId(), parsedJwt)
                    .thenApply(publicKey -> {
                        JWSVerifier jwsVerifier = getVerifier(parsedJwt.getHeader().getAlgorithm(), publicKey);
                        try {
                            if (!parsedJwt.verify(jwsVerifier)) {
                                throw new ClientResolutionException("Did not receive a valid authorization request.");
                            }
                            return objectMapper.readValue(parsedJwt.getPayload().toString(), AuthorizationRequest.class);

                        } catch (JsonProcessingException e) {
                            throw new BadGatewayException("Did not receive a valid authorization request.", e);

                        } catch (JOSEException e) {
                            throw new ClientResolutionException("Failed to validate authorization request.", e);
                        }
                    });
        } catch (ParseException e) {
            throw new ClientResolutionException("Was not ablet to parse the jwt.", e);
        }
    }

    /**
     * Get the AuthorizationRequest from the openid4vp query - either from the request_uri or directly encoded.
     */
    private CompletableFuture<AuthorizationRequest> getAuthorizationRequest(OpenId4VPQuery openId4VPQuery) {
        if (openId4VPQuery.getRequest() != null && !openId4VPQuery.getRequest().isEmpty()) {
            // get from JWT
            return handleAuthorizationRequestJWT(openId4VPQuery, openId4VPQuery.getRequest());
        } else if (openId4VPQuery.getRequestUri() != null && openId4VPQuery.getRequestUriMethod().equalsIgnoreCase("GET")) {
            // get from uri
            return requestAuthorizationRequest(openId4VPQuery.getRequestUri())
                    .thenCompose(jwt -> handleAuthorizationRequestJWT(openId4VPQuery, jwt));
        }
        throw new AuthorizationRequestException("Was not able to resolve the authentication request form the query.");
    }


    /**
     * Return the verifier, based on the algorithm and key provided.
     */
    private JWSVerifier getVerifier(JWSAlgorithm jwsAlgorithm, PublicKey publicKey) {
        // Select verifier based on key type
        if (jwsAlgorithm.getName().startsWith("RS")) { // RSA
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Expected an RSA public key for algorithm " + jwsAlgorithm);
            }
            return new RSASSAVerifier((RSAPublicKey) publicKey);
        } else if (jwsAlgorithm.getName().startsWith("ES")) { // ECDSA
            if (!(publicKey instanceof ECPublicKey)) {
                throw new IllegalArgumentException("Expected an EC public key for algorithm " + jwsAlgorithm);
            }
            try {
                return new ECDSAVerifier((ECPublicKey) publicKey);
            } catch (JOSEException e) {
                throw new IllegalArgumentException("Was not able to create an ECDSA verifier with the given key.", e);
            }
        } else if (jwsAlgorithm.getName().startsWith("HS")) { // HMAC (requires secret key)
            throw new IllegalArgumentException("HMAC requires a secret key, not a public key");
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + jwsAlgorithm);
        }
    }

    /**
     * Request the AuthorizationRequest-Object from the given request_uri
     */
    private CompletableFuture<String> requestAuthorizationRequest(URI requestUri) {
        HttpRequest authorizationRequestUri = HttpRequest.newBuilder(requestUri).GET().build();
        return httpClient.sendAsync(authorizationRequestUri, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() == 200) {
                        return response.body();
                    } else {
                        throw new BadGatewayException(
                                String.format("Was not able to retrieve authorization request from %s - status: %s",
                                        requestUri,
                                        response.statusCode()
                                ));
                    }
                });
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

    /**
     * Validate that the provided OpenId-Endpoint supports OpenId4VP
     */
    private void validateOpenIDConfiguration(OpenIdConfiguration openIdConfiguration, RequestParameters requestParameters) {
        if (openIdConfiguration.getAuthorizationEndpoint() == null) {
            throw new IllegalArgumentException(String.format("The OpenID configuration does not contain an authorization_endpoint: %s", openIdConfiguration));
        }
        if (openIdConfiguration.getTokenEndpoint() == null) {
            throw new IllegalArgumentException(String.format("The OpenID configuration does not contain an token_endpoint: %s", openIdConfiguration));
        }
        if (!openIdConfiguration.getScopesSupported().containsAll(requestParameters.scope())) {
            throw new IllegalArgumentException(String.format("The OpenID configuration does not support all required(%s) scopes: %s", requestParameters.scope(), openIdConfiguration));
        }
        if (!openIdConfiguration.getGrantTypesSupported().contains(VP_TOKEN_GRANT_TYPE)) {
            throw new IllegalArgumentException(String.format("The OpenID configuration does not support vp_token: %s", openIdConfiguration));
        }

        if (!openIdConfiguration.getResponseTypesSupported().contains(CODE_RESPONSE_TYPE)) {
            throw new IllegalArgumentException(String.format("The OpenID configuration does not support the response_type code: %s", openIdConfiguration));
        }
    }

}

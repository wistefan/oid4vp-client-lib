package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.exception.AuthorizationRequestException;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.AuthorizationRequest;
import io.github.wistefan.oid4vp.model.OpenId4VPQuery;
import io.github.wistefan.oid4vp.model.TokenResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static io.github.wistefan.oid4vp.HttpConstants.*;
import static io.github.wistefan.oid4vp.OID4VPClient.asJson;
import static io.github.wistefan.oid4vp.OIDConstants.LOCATION_HEADER;
import static io.github.wistefan.oid4vp.OIDConstants.OPENID_4_VP_SCHEME;

@Slf4j
@RequiredArgsConstructor
public class AuthorizationClient {

    private static final String ALGORITHM_INDICATOR_RS = "RS";
    private static final String ALGORITHM_INDICATOR_ES = "ES";

    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;
    private final List<ClientResolver> clientResolvers;

    public CompletableFuture<AuthorizationRequest> sendAuthorizationRequest(URI authorizationURI) {
        HttpRequest authorizationRequest = HttpRequest.newBuilder(authorizationURI).GET().build();

        return httpClient.sendAsync(authorizationRequest, HttpResponse.BodyHandlers.ofString())
                .thenCompose(response -> {
                    if (response.statusCode() == STATUS_CODE_REDIRECT) {
                        return handleAuthorizationRedirectResponse(response);
                    } else {
                        throw new BadGatewayException(
                                String.format("Was not able to get authorization response from %s - status: %s",
                                        authorizationURI,
                                        response.statusCode()
                                ));
                    }
                });
    }

    public CompletableFuture<TokenResponse> sendAuthorizationResponse(URI tokenEndpoint, String formData) {
        HttpRequest authorizationResponse = HttpRequest
                .newBuilder(tokenEndpoint)
                .header(CONTENT_TYPE_KEY, CONTENT_TYPE_FORM_ENCODED)
                .POST(HttpRequest.BodyPublishers.ofString(formData))
                .build();
        return httpClient.sendAsync(authorizationResponse, asJson(objectMapper, TokenResponse.class))
                .thenApply(response -> {
                    if (response.statusCode() == STATUS_CODE_OK) {
                        return response.body();
                    }
                    throw new AuthorizationException(String.format("Did not receive a successfully token response. Was: %s", response.statusCode()));
                });
    }

    /**
     * Handle redirects from the authorizationEndpoint towards OpendId4VP Deeplinks.
     */
    private CompletableFuture<AuthorizationRequest> handleAuthorizationRedirectResponse(HttpResponse<?> httpResponse) {
        if (httpResponse.statusCode() != STATUS_CODE_REDIRECT) {
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
     * Get the AuthorizationRequest from the openid4vp query - either from the request_uri or directly encoded.
     */
    private CompletableFuture<AuthorizationRequest> getAuthorizationRequest(OpenId4VPQuery openId4VPQuery) {
        if (openId4VPQuery.getRequest() != null && !openId4VPQuery.getRequest().isEmpty()) {
            // get from JWT
            return handleAuthorizationRequestJWT(openId4VPQuery, openId4VPQuery.getRequest());
        } else if (openId4VPQuery.getRequestUri() != null && openId4VPQuery.getRequestUriMethod().equalsIgnoreCase(HTTP_METHOD_GET)) {
            // get from uri
            return requestAuthorizationRequest(openId4VPQuery.getRequestUri())
                    .thenCompose(jwt -> handleAuthorizationRequestJWT(openId4VPQuery, jwt));
        }
        throw new AuthorizationRequestException("Was not able to resolve the authentication request form the query.");
    }

    /**
     * Request the AuthorizationRequest-Object from the given request_uri
     */
    private CompletableFuture<String> requestAuthorizationRequest(URI requestUri) {
        HttpRequest authorizationRequestUri = HttpRequest.newBuilder(requestUri).GET().build();
        return httpClient.sendAsync(authorizationRequestUri, HttpResponse.BodyHandlers.ofString())
                .thenApply(response -> {
                    if (response.statusCode() == STATUS_CODE_OK) {
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
            throw new ClientResolutionException("Was not able to parse the jwt.", e);
        }
    }

    /**
     * Return the verifier, based on the algorithm and key provided.
     */
    private JWSVerifier getVerifier(JWSAlgorithm jwsAlgorithm, PublicKey publicKey) {
        // Select verifier based on key type
        if (jwsAlgorithm.getName().startsWith(ALGORITHM_INDICATOR_RS)) { // RSA
            if (!(publicKey instanceof RSAPublicKey)) {
                throw new IllegalArgumentException("Expected an RSA public key for algorithm " + jwsAlgorithm);
            }
            return new RSASSAVerifier((RSAPublicKey) publicKey);
        } else if (jwsAlgorithm.getName().startsWith(ALGORITHM_INDICATOR_ES)) { // ECDSA
            if (!(publicKey instanceof ECPublicKey)) {
                throw new IllegalArgumentException("Expected an EC public key for algorithm " + jwsAlgorithm);
            }
            try {
                return new ECDSAVerifier((ECPublicKey) publicKey);
            } catch (JOSEException e) {
                throw new IllegalArgumentException("Was not able to create an ECDSA verifier with the given key.", e);
            }
        } else {
            throw new IllegalArgumentException("Unsupported algorithm: " + jwsAlgorithm);
        }
    }
}

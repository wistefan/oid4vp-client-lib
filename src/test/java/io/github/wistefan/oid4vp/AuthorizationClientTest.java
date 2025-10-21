package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.client.ClientResolverTest;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.exception.AuthorizationRequestException;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.AuthorizationRequest;
import io.github.wistefan.oid4vp.model.TokenResponse;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static com.nimbusds.jose.JWSAlgorithm.ES256;
import static com.nimbusds.jose.JWSAlgorithm.RS256;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class AuthorizationClientTest {

    private static final TestHelpers TEST_HELPERS = new TestHelpers();
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Mock
    private HttpClient httpClient;

    @Mock
    private ClientResolver clientResolver;

    private AuthorizationClient authorizationClient;

    @BeforeAll
    public static void addBouncyCastler() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        authorizationClient = new AuthorizationClient(httpClient, OBJECT_MAPPER, List.of(clientResolver));
    }

    @DisplayName("The authorization response should properly be sent.")
    @Test
    public void testSendAuthorizationResponse() throws Exception {
        TokenResponse tokenResponse = new TokenResponse();
        HttpResponse httpResponse = mock(HttpResponse.class);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(tokenResponse);

        when(httpClient.sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(httpResponse));

        assertEquals(tokenResponse,
                authorizationClient.sendAuthorizationResponse(URI.create("https://my-verifier.io/token"), "formData").get(),
                "A proper token should be responded.");

    }

    @DisplayName("If no token is responded, the an exception should be thrown.")
    @ParameterizedTest(name = "{index} - A {0} response should be responded with an exception.")
    @ValueSource(ints = {302, 400, 401, 403, 404, 500})
    public void testSendAuthorizationResponse(int statusCode) throws Exception {
        HttpResponse httpResponse = mock(HttpResponse.class);
        when(httpResponse.statusCode()).thenReturn(statusCode);

        when(httpClient.sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(httpResponse));

        assertThrows(
                AuthorizationException.class,
                () -> TEST_HELPERS.executeWithUnwrapping(URI.create("https://my-verifier.io/token"), "formData",
                        (uri, data) -> authorizationClient.sendAuthorizationResponse(uri, data)),
                "In non-ok responses, an AuthorizationException should be thrown.");
    }

    @DisplayName("Fails to the authorization endpoint should be properly handled, when request is provided by reference.")
    @ParameterizedTest(name = "{index} - {4}")
    @MethodSource("provideInvalidValidAuthorizationCallsByReference")
    public void testSendAuthorizationRequestErrorByReference(ClientResolution clientResolution, HttpResponse authorizationResponse, HttpResponse referenceResponse, Class<? extends RuntimeException> expectedException, String message) {

        // fails before second call when first is invalid
        lenient().when(httpClient.sendAsync(
                        any(),
                        any()))
                .thenReturn(CompletableFuture.completedFuture(authorizationResponse))
                .thenReturn(CompletableFuture.completedFuture(referenceResponse));

        // if first call already fails, no client resolution is required
        lenient().when(clientResolver.getPublicKey(any(), any())).thenReturn(clientResolution.resolution());
        lenient().when(clientResolver.isSupportedId(any())).thenReturn(clientResolution.supported());

        assertThrows(
                expectedException,
                () -> TEST_HELPERS.executeWithUnwrapping(URI.create("https://my-verifier.io/authorization"), u -> authorizationClient.sendAuthorizationRequest(u)),
                message);
    }

    @DisplayName("Fails to the authorization endpoint should be properly handled, when request is provided by value.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideInvalidValidAuthorizationCallsByValue")
    public void testSendAuthorizationRequestErrorByValue(ClientResolution clientResolution, HttpResponse authorizationResponse, Class<? extends RuntimeException> expectedException, String message) {

        // fails before second call when first is invalid
        lenient().when(httpClient.sendAsync(
                        any(),
                        any()))
                .thenReturn(CompletableFuture.completedFuture(authorizationResponse));

        // if first call already fails, no client resolution is required
        lenient().when(clientResolver.getPublicKey(any(), any())).thenReturn(clientResolution.resolution());
        lenient().when(clientResolver.isSupportedId(any())).thenReturn(clientResolution.supported());

        assertThrows(
                expectedException,
                () -> TEST_HELPERS.executeWithUnwrapping(URI.create("https://my-verifier.io/authorization"), u -> authorizationClient.sendAuthorizationRequest(u)),
                message);
    }

    private record ClientResolution(boolean supported, CompletableFuture resolution) {
    }

    private static Stream<Arguments> provideInvalidValidAuthorizationCallsByValue() throws Exception {
        KeyPair rsaKeyPair = ClientResolverTest.getRSAKey();
        KeyPair ecKeyPair = ClientResolverTest.getECKey();

        return Stream.of(
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(200),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return a redirect."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(400),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return a redirect."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of(toByReferenceURI("my-verifier.io", "get", "https"))),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return an openid4vp uri."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.empty()),
                        BadGatewayException.class,
                        "If no location header is returned, the response is invalid."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of("openid4vp://my-verifier.io?incomplete=request")),
                        AuthorizationRequestException.class,
                        "If the location header does not contain a valid openid4vp query."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of(toJwtURI("noJwt"))),
                        ClientResolutionException.class,
                        "If no valid jwt is provided, an error should be thrown."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(ClientResolverTest.getRSAKey().getPublic())),
                        mockResponse(302, Optional.of(toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize()))),
                        ClientResolutionException.class,
                        "If the jwt is not correctly signed, an error should be thrown."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.failedFuture(new ClientResolutionException("Not my client."))),
                        mockResponse(302, Optional.of(toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize()))),
                        ClientResolutionException.class,
                        "If client resolver throws an expcted exception, it should bubble."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.failedFuture(new RuntimeException("Cannot run in time."))),
                        mockResponse(302, Optional.of(toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize()))),
                        ClientResolutionException.class,
                        "If client resolver throws an unexpected exception, it should be properly wrapped."
                )
        );
    }

    private static Stream<Arguments> provideInvalidValidAuthorizationCallsByReference() throws Exception {
        KeyPair rsaKeyPair = ClientResolverTest.getRSAKey();
        KeyPair ecKeyPair = ClientResolverTest.getECKey();

        return Stream.of(
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(200),
                        mockResponse(200),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return a redirect."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(400),
                        mockResponse(200),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return a redirect."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of(toByReferenceURI("my-verifier.io", "get", "https"))),
                        mockResponse(200),
                        BadGatewayException.class,
                        "The authorization endpoint needs to return an openid4vp uri."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.empty()),
                        mockResponse(200),
                        BadGatewayException.class,
                        "If no location header is returned, the response is invalid."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of("openid4vp://my-verifier.io?incomplete=request")),
                        mockResponse(200),
                        AuthorizationRequestException.class,
                        "If the location header does not contain a valid openid4vp query."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302, Optional.of(toByReferenceURI("my-verifier.io", "post", "openid4vp"))),
                        mockResponse(200),
                        AuthorizationRequestException.class,
                        "Only `get` is supported for reference-resolution."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302),
                        mockResponse(400),
                        BadGatewayException.class,
                        "If the reference cannot be resolved, an error should be provided."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302),
                        mockResponse(200, Optional.empty(), Optional.empty()),
                        ClientResolutionException.class,
                        "If an empty body is returned from the reference, an error should be provided."
                ),
                Arguments.of(
                        new ClientResolution(false, CompletableFuture.completedFuture(rsaKeyPair.getPublic())),
                        mockResponse(302),
                        mockResponse(200, Optional.empty(), Optional.of(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize())),
                        ClientResolutionException.class,
                        "If an unsupported clientId is returned, an error should be thrown."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(ecKeyPair.getPublic())),
                        mockResponse(302),
                        mockResponse(200, Optional.empty(), Optional.of(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize())),
                        ClientResolutionException.class,
                        "If request signed by the wrong key(different type) is provided, an error should be thrown."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.completedFuture(ClientResolverTest.getRSAKey().getPublic())),
                        mockResponse(302),
                        mockResponse(200, Optional.empty(), Optional.of(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize())),
                        ClientResolutionException.class,
                        "If request signed by the wrong key(same type) is provided, an error should be thrown."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.failedFuture(new ClientResolutionException("Not my client."))),
                        mockResponse(302, Optional.of(toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize()))),
                        mockResponse(200),
                        ClientResolutionException.class,
                        "If client resolver throws an expcted exception, it should bubble."
                ),
                Arguments.of(
                        new ClientResolution(true, CompletableFuture.failedFuture(new RuntimeException("Cannot run in time."))),
                        mockResponse(302, Optional.of(toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, getAuthorizationRequest()).serialize()))),
                        mockResponse(200),
                        ClientResolutionException.class,
                        "If client resolver throws an unexpected exception, it should be properly wrapped."
                )
        );
    }

    @DisplayName("Calling the authorization endpoint should return a proper authorization request, when request is provided by reference.")
    @ParameterizedTest(name = "{index} - {4}")
    @MethodSource("provideValidAuthorizationCallsByReference")
    public void testSendAuthorizationRequestByReference(String locationResponse, PublicKey publicKey, String theJwt, AuthorizationRequest expectedRequest, String message) throws Exception {
        when(clientResolver.getPublicKey(any(), any())).thenReturn(CompletableFuture.completedFuture(publicKey));
        when(clientResolver.isSupportedId(any())).thenReturn(true);

        HttpResponse httpResponse = mock(HttpResponse.class);
        when(httpResponse.statusCode()).thenReturn(302);
        when(httpResponse.headers()).thenReturn(HttpHeaders.of(Map.of("Location", List.of(locationResponse)), (a, b) -> true));

        HttpResponse jwtResponse = mock(HttpResponse.class);
        when(jwtResponse.statusCode()).thenReturn(200);
        when(jwtResponse.body()).thenReturn(theJwt);

        // authorize call
        when(httpClient.sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(httpResponse));
        // resolve reference
        when(httpClient.sendAsync(
                argThat(req -> req.uri().toString().equals("https://my-verifier.org/ar-id")),
                any()))
                .thenReturn(CompletableFuture.completedFuture(jwtResponse));

        assertEquals(expectedRequest, authorizationClient.sendAuthorizationRequest(URI.create("https://my-verifier.io/authorization")).get(), message);
    }

    @DisplayName("Calling the authorization endpoint should return a proper authorization request, when request is provided by value.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideValidAuthorizationCallsEncoded")
    public void testSendAuthorizationRequestEncoded(String locationResponse, PublicKey publicKey, AuthorizationRequest expectedRequest, String message) throws Exception {
        HttpResponse httpResponse = mock(HttpResponse.class);
        when(httpResponse.statusCode()).thenReturn(302);
        when(httpResponse.headers()).thenReturn(HttpHeaders.of(Map.of("Location", List.of(locationResponse)), (a, b) -> true));
        when(clientResolver.getPublicKey(any(), any())).thenReturn(CompletableFuture.completedFuture(publicKey));
        when(clientResolver.isSupportedId(any())).thenReturn(true);

        when(httpClient.sendAsync(any(), any())).thenReturn(CompletableFuture.completedFuture(httpResponse));

        assertEquals(expectedRequest, authorizationClient.sendAuthorizationRequest(URI.create("https://my-verifier.io/authorization")).get(), message);
    }


    private static HttpResponse mockResponse(int statusCode) {
        return mockResponse(statusCode, Optional.of(toByReferenceURI("https://my-verifier.org/ar-id")));
    }

    private static HttpResponse mockResponse(int statusCode, Optional<String> optionalUri, Optional<String> optionalBody) {
        HttpResponse httpResponse = mock(HttpResponse.class);
        when(httpResponse.statusCode()).thenReturn(statusCode);
        optionalUri.ifPresentOrElse(
                uri -> when(httpResponse.headers()).thenReturn(HttpHeaders.of(Map.of("Location", List.of(uri)), (a, b) -> true)),
                () -> when(httpResponse.headers()).thenReturn(HttpHeaders.of(Map.of(), (a, b) -> true)));
        optionalBody.ifPresentOrElse(
                body -> when(httpResponse.body()).thenReturn(body),
                () -> when(httpResponse.body()).thenReturn("")
        );
        return httpResponse;
    }

    private static HttpResponse mockResponse(int statusCode, Optional<String> optionalUri) {
        return mockResponse(statusCode, optionalUri, Optional.empty());
    }

    private static Stream<Arguments> provideValidAuthorizationCallsByReference() throws Exception {
        KeyPair rsaKeyPair = ClientResolverTest.getRSAKey();
        KeyPair ecKeyPair = ClientResolverTest.getECKey();

        AuthorizationRequest authorizationRequest = getAuthorizationRequest();

        SignedJWT ecJwt = getAuthorizationRequestJwt(ecKeyPair, ES256, authorizationRequest);
        SignedJWT rsaJwt = getAuthorizationRequestJwt(rsaKeyPair, RS256, authorizationRequest);

        return Stream.of(
                Arguments.of(
                        toByReferenceURI("https://my-verifier.org/ar-id"),
                        rsaKeyPair.getPublic(),
                        rsaJwt.serialize(),
                        authorizationRequest,
                        "The authorization request should be retrieved from the reference when RSA signed."
                ),
                Arguments.of(
                        toByReferenceURI("https://my-verifier.org/ar-id"),
                        ecKeyPair.getPublic(),
                        ecJwt.serialize(),
                        authorizationRequest,
                        "The authorization request should be retrieved from the uri when EC signed."
                )
        );
    }

    private static AuthorizationRequest getAuthorizationRequest() {
        AuthorizationRequest authorizationRequest = new AuthorizationRequest()
                .setResponseMode("direct_post")
                .setResponseType("vp_token")
                .setState("state")
                .setNonce("nonce")
                .setClientId("test-client");
        return authorizationRequest;
    }

    private static Stream<Arguments> provideValidAuthorizationCallsEncoded() throws Exception {
        KeyPair rsaKeyPair = ClientResolverTest.getRSAKey();
        KeyPair ecKeyPair = ClientResolverTest.getECKey();

        AuthorizationRequest authorizationRequest = getAuthorizationRequest();

        return Stream.of(
                Arguments.of(
                        toJwtURI(getAuthorizationRequestJwt(rsaKeyPair, RS256, authorizationRequest).serialize()),
                        rsaKeyPair.getPublic(),
                        authorizationRequest,
                        "The authorization request should be retrieved from the uri when RSA signed."
                ),
                Arguments.of(
                        toJwtURI(getAuthorizationRequestJwt(ecKeyPair, ES256, authorizationRequest).serialize()),
                        ecKeyPair.getPublic(),
                        authorizationRequest,
                        "The authorization request should be retrieved from the uri when EC signed."
                )
        );
    }

    private static String toJwtURI(String jwt) {
        return toJwtURI(jwt, "openid4vp");
    }

    private static String toJwtURI(String jwt, String requestScheme) {
        return String.format("%s://my-verifier.io?client_id=test-client&request=%s", requestScheme, jwt);
    }

    private static String toByReferenceURI(String requestUri) {
        return toByReferenceURI(requestUri, "get", "openid4vp");
    }

    private static String toByReferenceURI(String requestUri, String requestMethod, String requestScheme) {
        return String.format("%s://my-verifier.io?client_id=test-client&request_uri=%s&request_uri_method=%s", requestScheme, requestUri, requestMethod);
    }

    private static SignedJWT getAuthorizationRequestJwt(KeyPair keyPair, JWSAlgorithm algorithm, AuthorizationRequest authorizationRequest) throws Exception {
        return getSignedJwt(keyPair, algorithm, authorizationRequest);
    }

    private static SignedJWT getSignedJwt(KeyPair keyPair, JWSAlgorithm algorithm, Object body) throws Exception {
        JWSHeader jwsHeaders = new JWSHeader.Builder(algorithm)
                .type(JOSEObjectType.JWT)
                .build();

        JWTClaimsSet.Builder jwtBuilder = new JWTClaimsSet.Builder();

        OBJECT_MAPPER.convertValue(body, new TypeReference<Map<String, Object>>() {
                })
                .forEach(jwtBuilder::claim);

        JWSSigner jwsSigner = switch (algorithm.getName()) {
            case "RS256" -> new RSASSASigner(keyPair.getPrivate());
            case "ES256" -> new ECDSASigner((ECPrivateKey) keyPair.getPrivate());
            default -> throw new IllegalArgumentException();
        };

        SignedJWT signedJWT = new SignedJWT(jwsHeaders, jwtBuilder.build());
        signedJWT.sign(jwsSigner);
        return signedJWT;
    }
}
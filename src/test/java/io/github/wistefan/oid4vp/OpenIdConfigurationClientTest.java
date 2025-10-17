package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.Oid4VPException;
import io.github.wistefan.oid4vp.model.OpenIdConfiguration;
import org.checkerframework.checker.units.qual.A;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.function.Function;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OpenIdConfigurationClientTest {

    @Mock
    private HttpClient httpClient;

    private OpenIdConfigurationClient openIdConfigurationClient;
    private ObjectMapper objectMapper;


    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();
        openIdConfigurationClient = new OpenIdConfigurationClient(httpClient, objectMapper);
    }


    @DisplayName("The OpenId Configuration should be returned correctly.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideValidRequests")
    public void testGetOpenIdConfiguration(RequestParameters requestParameters, OpenIdConfiguration response, URI expectedRequest, String message) throws Exception {

        HttpResponse<OpenIdConfiguration> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn(response);
        when(mockResponse.statusCode()).thenReturn(200);
        when(httpClient.sendAsync(
                argThat(req -> req.uri().toString().equals(expectedRequest.toString())),
                any(HttpResponse.BodyHandler.class)
        )).thenReturn(CompletableFuture.completedFuture(mockResponse));

        assertEquals(response, openIdConfigurationClient.getOpenIdConfiguration(requestParameters).get(), message);
    }

    @DisplayName("Invalid OpenId Configurations should lead to failure.")
    @ParameterizedTest(name = "{index} - {4}")
    @MethodSource("provideInvalidRequests")
    public void testGetOpenIdConfigurationError(RequestParameters requestParameters, OpenIdConfiguration response, int responseCode, Class<? extends RuntimeException> expectedException, String message) throws Exception {

        HttpResponse<OpenIdConfiguration> mockResponse = mock(HttpResponse.class);
        // when the status indicates an error, the body is not read
        lenient().when(mockResponse.body()).thenReturn(response);
        // for invalid params, no request is sent at all
        lenient().when(mockResponse.statusCode()).thenReturn(responseCode);
        lenient().when(httpClient.sendAsync(
                any(),
                any(HttpResponse.BodyHandler.class)
        )).thenReturn(CompletableFuture.completedFuture(mockResponse));
        assertThrows(expectedException, () -> executeWithUnwrapping(requestParameters, rp -> openIdConfigurationClient.getOpenIdConfiguration(rp)), message);
    }

    private <P, T> T executeWithUnwrapping(P parameter, Function<P, CompletableFuture<T>> functionToExecute) throws Throwable {
        try {
            return functionToExecute.apply(parameter).get();
        } catch (CompletionException | ExecutionException e) {
            throw e.getCause();
        }
    }

    private static RequestParameters getValidRequestParameters() {
        return new RequestParameters(URI.create("https://test.io"), "", "test", Set.of("openid", "test"));
    }

    private static Stream<Arguments> provideInvalidRequests() {
        return Stream.of(
                Arguments.of(
                        getValidRequestParameters(),
                        new OpenIdConfiguration(),
                        200,
                        BadGatewayException.class,
                        "An empty OpenId-Configuration is invalid."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")),
                        400,
                        BadGatewayException.class,
                        "If no valid response is returned, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid")),
                        200,
                        BadGatewayException.class,
                        "If not all requested scopes are supported, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setAuthorizationEndpoint(null),
                        200,
                        BadGatewayException.class,
                        "If no authorization_endpoint is provided, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setTokenEndpoint(null),
                        200,
                        BadGatewayException.class,
                        "If no token_endpoint is provided, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(null),
                        200,
                        BadGatewayException.class,
                        "If no scopes are provided, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setGrantTypesSupported(null),
                        200,
                        BadGatewayException.class,
                        "If no grant_types are provided, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setResponseTypesSupported(null),
                        200,
                        BadGatewayException.class,
                        "If no response_types are provided, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setGrantTypesSupported(Set.of("unsupported")),
                        200,
                        BadGatewayException.class,
                        "If grant_types does not support vp_token, an error should be thrown."),
                Arguments.of(
                        getValidRequestParameters(),
                        getValidOpenIdConfiguration(Set.of("openid", "test")).setResponseTypesSupported(Set.of("unsupported")),
                        200,
                        BadGatewayException.class,
                        "If response_types does not support code, an error should be thrown."),
                Arguments.of(
                        new RequestParameters(null, "", "test", Set.of("openid")),
                        getValidOpenIdConfiguration(Set.of("openid", "test")),
                        200,
                        Oid4VPException.class,
                        "If no host is requested, an error should be thrown.")
        );
    }


    private static Stream<Arguments> provideValidRequests() {
        return Stream.of(
                Arguments.of(
                        new RequestParameters(URI.create("https://test.io"), "", "test", Set.of("openid", "test")),
                        getValidOpenIdConfiguration(Set.of("openid", "test")),
                        URI.create("https://test.io/.well-known/openid-configuration"),
                        "The configuration should be returned directly under the host."
                ),
                Arguments.of(
                        new RequestParameters(URI.create("https://test.io"), "/my/service", "test", Set.of("openid", "test")),
                        getValidOpenIdConfiguration(Set.of("openid", "test")),
                        URI.create("https://test.io/my/service/.well-known/openid-configuration"),
                        "The configuration should be returned from the requested sub-path."
                ),
                Arguments.of(
                        new RequestParameters(URI.create("https://test.io"), "/my/service", "test", null),
                        getValidOpenIdConfiguration(Set.of("openid", "test")),
                        URI.create("https://test.io/my/service/.well-known/openid-configuration"),
                        "If no specific scopes are requested, the authorization server needs to decide upon."
                )
        );
    }

    private static OpenIdConfiguration getValidOpenIdConfiguration(Set<String> supportedScopes) {
        return new OpenIdConfiguration()
                .setAuthorizationEndpoint(URI.create("https://verifier.io/authorization"))
                .setTokenEndpoint(URI.create("https://verifier.io/token"))
                .setScopesSupported(supportedScopes)
                .setGrantTypesSupported(Set.of("vp_token"))
                .setResponseTypesSupported(Set.of("code"));
    }

}
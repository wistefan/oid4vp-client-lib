package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.PropertyNamingStrategies;
import com.fasterxml.jackson.databind.module.SimpleModule;
import io.github.wistefan.dcql.*;
import io.github.wistefan.dcql.model.*;
import io.github.wistefan.dcql.model.credential.CredentialBase;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.config.RequestParameters;
import io.github.wistefan.oid4vp.credentials.CredentialsRepository;
import io.github.wistefan.oid4vp.exception.*;
import io.github.wistefan.oid4vp.mapping.CredentialFormatDeserializer;
import io.github.wistefan.oid4vp.mapping.TrustedAuthorityTypeDeserializer;
import io.github.wistefan.oid4vp.model.AuthorizationRequest;
import io.github.wistefan.oid4vp.model.OpenIdConfiguration;
import io.github.wistefan.oid4vp.model.TokenResponse;
import io.github.wistefan.oid4vp.model.VerifiablePresentation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.concurrent.CompletableFuture;
import java.util.stream.Stream;

import static io.github.wistefan.oid4vp.OIDConstants.*;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class OID4VPClientTest {

    private static final TestHelpers TEST_HELPERS = new TestHelpers();

    @Mock
    private HolderConfiguration holderConfiguration;

    @Mock
    private CredentialsRepository credentialsRepository;

    @Mock
    private SigningService signingService;

    @Mock
    private OpenIdConfigurationClient openIdConfigurationClient;

    @Mock
    private AuthorizationClient authorizationClient;

    @Mock
    private CryptoUtils cryptoUtils;

    private OID4VPClient oid4VPClient;
    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();
        objectMapper.setPropertyNamingStrategy(PropertyNamingStrategies.SNAKE_CASE);
        SimpleModule deserializerModule = new SimpleModule();
        deserializerModule.addDeserializer(CredentialFormat.class, new CredentialFormatDeserializer());
        deserializerModule.addDeserializer(TrustedAuthorityType.class, new TrustedAuthorityTypeDeserializer());
        objectMapper.registerModule(deserializerModule);

        DCQLEvaluator dcqlEvaluator = new DCQLEvaluator(List.of(
                new JwtCredentialEvaluator(),
                new DcSdJwtCredentialEvaluator(),
                new VcSdJwtCredentialEvaluator(),
                new MDocCredentialEvaluator(),
                new LdpCredentialEvaluator()));

        oid4VPClient = new OID4VPClient(holderConfiguration, objectMapper, dcqlEvaluator, credentialsRepository, signingService, openIdConfigurationClient, authorizationClient, cryptoUtils);
    }

    @DisplayName("When the DCQL cannot be fulfilled, correctly hanlde the error.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideUnsatisfiedQueries")
    public void testGetAccessTokenErrorUnsatisfiedDcql(Optional<DcqlQuery> dcqlQuery, List<Credential> credentialsRepo, Class<? extends RuntimeException> expectedException, String message) {

        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(Set.of("openid", "test"), verifierHost, authorizationPath);

        // mock the authorization request from the verifier
        AuthorizationRequest authorizationRequest = new AuthorizationRequest()
                .setClientId("did:web:my-verifier.org")
                .setNonce("nonce")
                .setState("state")
                .setResponseType("vp_token")
                .setResponseMode("direct_post");

        dcqlQuery.ifPresent(authorizationRequest::setDcqlQuery);
        mockCryptoUtils("state", "nonce");
        mockAuthorizationRequest(requestParameters, verifierHost, authorizationPath, authorizationRequest);
        mockCredentialRepository(credentialsRepo);

        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
        // assert that nothing fails before out mocked error.
        verify(credentialsRepository, times(1)).getCredentials();
    }

    @DisplayName("Assure failures sending the authorization response are handled correctly.")
    @ParameterizedTest(name = "{index} - {3}")
    @MethodSource("provideAuthorizationRequestAndExceptions")
    public void testGetAccessTokenErrorToken(AuthorizationRequest authorizationRequest, Throwable toBeThrown, Class<? extends RuntimeException> expectedException, String message) {

        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(Set.of("openid", "test"), verifierHost, authorizationPath);

        mockCryptoUtils("state", "nonce");
        when(authorizationClient.sendAuthorizationRequest(any())).thenReturn(CompletableFuture.completedFuture(authorizationRequest));

        mockCredentialRepository(List.of(getSingleSDCredential()));

        // in case of invalid AuthorizationRequest's the exception is thrown before the signature
        lenient().when(signingService.signPresentation(any())).thenReturn("signedToken");

        if (toBeThrown != null) {
            when(authorizationClient.sendAuthorizationResponse(any(), any())).thenThrow(toBeThrown);
        }
        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
    }


    @DisplayName("Assure failures signing the token are handled correctly.")
    @ParameterizedTest(name = "{index} - {2}")
    @MethodSource("provideRuntimeExceptions")
    public void testGetAccessTokenErrorSigningService(RuntimeException toBeThrown, Class<? extends RuntimeException> expectedException, String message) {

        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(Set.of("openid", "test"), verifierHost, authorizationPath);

        // mock the authorization request from the verifier
        AuthorizationRequest authorizationRequest = new AuthorizationRequest()
                .setClientId("did:web:my-verifier.org")
                .setState("state")
                .setNonce("nonce")
                .setResponseType("vp_token")
                .setResponseMode("direct_post");

        mockCryptoUtils("state", "nonce");
        mockAuthorizationRequest(requestParameters, verifierHost, authorizationPath, authorizationRequest);
        mockCredentialRepository(List.of(getSingleSDCredential()));

        when(signingService.signPresentation(any())).thenThrow(toBeThrown);

        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
        // assert that nothing fails before out mocked error.
        verify(signingService, times(1)).signPresentation(any());
    }

    @DisplayName("Assure failures in the credentials repo are handled correctly.")
    @ParameterizedTest(name = "{index} - {2}")
    @MethodSource("provideRuntimeExceptions")
    public void testGetAccessTokenErrorCredentialsRepo(RuntimeException toBeThrown, Class<? extends RuntimeException> expectedException, String message) {

        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(Set.of("openid", "test"), verifierHost, authorizationPath);

        // mock the authorization request from the verifier
        AuthorizationRequest authorizationRequest = new AuthorizationRequest()
                .setDcqlQuery(getTypeQuery(false, List.of(List.of("MyCredential"))))
                .setClientId("did:web:my-verifier.org")
                .setNonce("nonce")
                .setState("state")
                .setResponseType("vp_token")
                .setResponseMode("direct_post");

        mockCryptoUtils("state", "nonce");
        mockAuthorizationRequest(requestParameters, verifierHost, authorizationPath, authorizationRequest);

        when(credentialsRepository.getCredentials()).thenThrow(toBeThrown);

        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
        // assert that nothing fails before out mocked error.
        verify(credentialsRepository, times(1)).getCredentials();
    }

    @DisplayName("Assure failures sending the authorization request are handled correctly.")
    @ParameterizedTest(name = "{index} - {2}")
    @MethodSource("provideExceptions")
    public void testGetAccessTokenErrorAuthorization(Throwable toBeThrown, Class<? extends RuntimeException> expectedException, String message) {

        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(Set.of("openid", "test"), verifierHost, authorizationPath);
        mockCryptoUtils("state", "nonce");

        CompletableFuture<AuthorizationRequest> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(toBeThrown);
        when(authorizationClient.sendAuthorizationRequest(any())).thenReturn(failedFuture);

        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
        // assert that nothing fails before out mocked error.
        verify(authorizationClient, times(1)).sendAuthorizationRequest(any());
    }

    @DisplayName("Assure failures requesting the OpenId Config are handled correctly.")
    @ParameterizedTest(name = "{index} - {2}")
    @MethodSource("provideExceptions")
    public void testGetAccessTokenErrorConfig(Throwable toBeThrown, Class<? extends RuntimeException> expectedException, String message) {
        RequestParameters requestParameters = new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test"));

        CompletableFuture<OpenIdConfiguration> failedFuture = new CompletableFuture<>();
        failedFuture.completeExceptionally(toBeThrown);
        when(openIdConfigurationClient.getOpenIdConfiguration(any()))
                .thenReturn(failedFuture);
        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(requestParameters, rp -> oid4VPClient.getAccessToken(rp)), message);
        // assert that nothing fails before out mocked error.
        verify(openIdConfigurationClient, times(1)).getOpenIdConfiguration(any());
    }

    @DisplayName("Assert that an access token can successfully be retrieved.")
    @ParameterizedTest
    @MethodSource("provideRequestParameters")
    public void testGetAccessToken(RequestParameters requestParameters, Set<String> scopes, Optional<DcqlQuery> dcqlQuery, List<Credential> credentialsRepo, List<String> expectedCredentials) throws Exception {
        String verifierHost = "my-verifier.io";
        String authorizationPath = "/authorization";

        mockOpenIdConfiguration(scopes, verifierHost, authorizationPath);

        // mock the authorization request from the verifier
        AuthorizationRequest authorizationRequest = new AuthorizationRequest()
                .setClientId("did:web:my-verifier.org")
                .setNonce("nonce")
                .setState("state")
                .setResponseType("vp_token")
                .setResponseMode("direct_post");
        dcqlQuery.ifPresent(authorizationRequest::setDcqlQuery);

        mockCryptoUtils("state", "nonce");
        mockAuthorizationRequest(requestParameters, verifierHost, authorizationPath, authorizationRequest);
        mockCredentialRepository(credentialsRepo);

        // assert that the credentials are provided to the signing-service
        String mockToken = "signedToken";
        when(signingService.signPresentation(any())).thenReturn(mockToken);


        // mock the token response
        TokenResponse tokenResponse = new TokenResponse()
                .setAccessToken("myAccessToken")
                .setIdToken("myIdToken")
                .setTokenType("Bearer");
        mockAuthorizationResponse(requestParameters, mockToken, tokenResponse, dcqlQuery);

        assertEquals(tokenResponse, oid4VPClient.getAccessToken(requestParameters).get(), "A token response should be returned.");
        assertCorrectCredentialsProvided(expectedCredentials);
    }


    private static Stream<Arguments> provideAuthorizationRequestAndExceptions() {
        return Stream.concat(provideRuntimeExceptions()
                        .map(a -> {
                            Object[] newArgs = new Object[a.get().length + 1];
                            newArgs[0] = getValidAuthorizationRequest();
                            System.arraycopy(a.get(), 0, newArgs, 1, a.get().length);
                            return Arguments.of(newArgs);
                        }),
                Stream.of(
                        Arguments.of(new AuthorizationRequest(), null, AuthorizationRequestException.class,
                                "If not valid request is provided, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setResponseMode("unsupported_mode"), null, AuthorizationRequestException.class,
                                "If an unsupported mode is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setResponseType("unsupported_type"), null, AuthorizationRequestException.class,
                                "If an unsupported response_type is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setState("wrongState"), null, AuthorizationRequestException.class,
                                "If the wrong state is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setState("wrongNonce"), null, AuthorizationRequestException.class,
                                "If the wrong nonce is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setResponseMode(null), null, AuthorizationRequestException.class,
                                "If an null mode is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setResponseType(null), null, AuthorizationRequestException.class,
                                "If an null response_type is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setState(null), null, AuthorizationRequestException.class,
                                "If a null state is requested, nothing should be presented."),
                        Arguments.of(getValidAuthorizationRequest().setState(null), null, AuthorizationRequestException.class,
                                "If a null nonce is requested, nothing should be presented.")
                )
        );
    }

    private static AuthorizationRequest getValidAuthorizationRequest() {
        return new AuthorizationRequest()
                .setClientId("did:web:verifier.io")
                .setResponseMode(RESPONSE_MODE_DIRECT_POST)
                .setState("state")
                .setNonce("nonce")
                .setResponseType(RESPONSE_TYPE_VP_TOKEN);
    }

    private static Stream<Arguments> provideRuntimeExceptions() {
        return Stream.of(Arguments.of(new RuntimeException("Something unexpected."), Oid4VPException.class, "Unspecific exceptions should be thrown as Oid4VPExceptions."),
                Arguments.of(new IllegalArgumentException("Cannot understand you."), Oid4VPException.class, "Unspecific exceptions should be thrown as Oid4VPExceptions."),
                Arguments.of(new BadGatewayException("Naughty gateway is evil."), BadGatewayException.class, "Specific exceptions should just bubble."),
                Arguments.of(new AuthorizationException("Cannot authorize:(."), AuthorizationException.class, "Specific exceptions should just bubble."),
                Arguments.of(new AuthorizationRequestException("Cannot understand the request to authorize."), AuthorizationRequestException.class, "Specific exceptions should just bubble."),
                Arguments.of(new ClientResolutionException("Who's asking?"), ClientResolutionException.class, "Specific exceptions should just bubble."),
                Arguments.of(new CredentialsAccessException("Stay away from my secrets!"), CredentialsAccessException.class, "Specific exceptions should just bubble.")
        );
    }

    private static Stream<Arguments> provideExceptions() {
        return Stream.concat(
                Stream.of(
                        Arguments.of(new Throwable("Something wild."), Oid4VPException.class, "Unspecific exceptions should be thrown as Oid4VPExceptions."),
                        Arguments.of(new Exception("Something less wild."), Oid4VPException.class, "Unspecific exceptions should be thrown as Oid4VPExceptions.")),
                provideRuntimeExceptions());
    }

    private void mockAuthorizationResponse(RequestParameters requestParameters, String mockToken, TokenResponse tokenResponse, Optional<DcqlQuery> requestedQuery) throws Exception {
        when(authorizationClient.sendAuthorizationResponse(
                argThat(uri -> uri.toString().equals("https://my-verifier.io/token")),
                argThat(formData -> {
                    Map<String, String> dataMap = fromData(formData);
                    assertTrue(compareScope(
                                    dataMap.get("scope"),
                                    requestParameters.scope()),
                            "The scope provided by the request-parameters should be provided in the authorization response.");
                    assertEquals(
                            requestParameters.clientId(),
                            dataMap.get("client_id"),
                            "The client_id provided by the request-parameters should be provided in the authorization response.");
                    try {
                        assertCorrectToken(dataMap.get("vp_token"), mockToken, requestedQuery);
                    } catch (Exception e) {
                        fail(e);
                    }
                    return true;
                }))).thenReturn(CompletableFuture.completedFuture(tokenResponse));
    }

    private void assertCorrectToken(String theToken, String theMockToken, Optional<DcqlQuery> requestedDcql) throws Exception {
        String decodedToken = URLDecoder.decode(theToken, StandardCharsets.UTF_8);

        if (requestedDcql.isEmpty() || requestedDcql.get().getCredentialSets() == null || requestedDcql.get().getCredentialSets().isEmpty()) {
            assertEquals(theMockToken, decodedToken, "In case no credential set is requested, only the token should be returned.");
        } else {
            Map<String, String> resultMap = objectMapper.readValue(Base64.getUrlDecoder().decode(decodedToken), new TypeReference<Map<String, String>>() {
            });
            List<String> purposes = requestedDcql.get().getCredentialSets()
                    .stream()
                    .map(CredentialSetQuery::getPurpose)
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
            assertEquals(purposes.size(), resultMap.keySet().size(), "Credentials for all requested sets should be included.");
            purposes
                    .forEach(purpose -> assertEquals(theMockToken, resultMap.get(purpose),
                            "The correct token should be provided for the purpose."));
        }
    }

    private static Stream<Arguments> provideUnsatisfiedQueries() {
        DcqlQuery emptyListQuery = getInvalidQuery();
        emptyListQuery.setCredentials(List.of());
        return Stream.of(
                Arguments.of(
                        Optional.of(getFormatQuery(false, CredentialFormat.JWT_VC_JSON)), getMultipleCredentials(),
                        AuthorizationException.class,
                        "Multiple credentials would be returned, should not succeed."),
                Arguments.of(
                        Optional.of(getTypeQuery(true, List.of(List.of("SomeUnknownType")))), getMultipleCredentials(),
                        AuthorizationException.class,
                        "No such credential can be found, should not succeed."),
                Arguments.of(
                        Optional.of(getInvalidQuery()), getMultipleCredentials(),
                        Oid4VPException.class,
                        "Invalid queries should not return anything."),
                Arguments.of(
                        Optional.of(emptyListQuery), getMultipleCredentials(),
                        Oid4VPException.class,
                        "Invalid queries should not return anything.")
        );
    }

    private void assertCorrectCredentialsProvided(List<String> expectedCredentials) {

        List<String> providedCredentials = new ArrayList<>();
        mockingDetails(signingService)
                .getInvocations()
                .forEach(invocation ->
                        Arrays.stream(invocation.getArguments())
                                .filter(VerifiablePresentation.class::isInstance)
                                .map(VerifiablePresentation.class::cast)
                                .map(VerifiablePresentation::getVerifiableCredential)
                                .filter(Objects::nonNull)
                                .flatMap(List::stream)
                                .filter(String.class::isInstance)
                                .map(String.class::cast)
                                .forEach(providedCredentials::add)
                );
        assertEquals(
                expectedCredentials.size(),
                providedCredentials.stream()
                        .filter(expectedCredentials::contains)
                        .toList()
                        .size(),
                "Only the queried credentials should be provided.");
    }

    private void mockCryptoUtils(String state, String nonce) {
        when(cryptoUtils.generateRandomString(anyInt()))
                // order is important, needs to match the implementation
                .thenReturn(state)
                .thenReturn(nonce);
    }

    private void mockAuthorizationRequest(RequestParameters requestParameters, String verifierHost, String authorizationPath, AuthorizationRequest authorizationRequest) {

        when(authorizationClient.sendAuthorizationRequest(argThat(uri -> {
            // assure that the request was built correctly
            assertEquals("https", uri.getScheme(), "Authorization requests must use http.");
            assertEquals(verifierHost, uri.getAuthority(), "The Authorization request should be sent to the authority provided by the openid-configuration.");
            assertEquals(authorizationPath, uri.getPath(), "The Authorization request should be sent to the authorization-path provided by the openid-configuration.");
            Map<String, String> queryMap = fromData(uri.getQuery());
            assertTrue(queryMap.containsKey("state"), "A state should be provided as a query-parameter.");
            assertTrue(queryMap.containsKey("nonce"), "A nonce should be provided as a query-parameter.");
            assertEquals(requestParameters.clientId(), queryMap.get("client_id"), "The clientId provided by the request-parameters should be provided as a query-parameter.");
            assertTrue(compareScope(queryMap.get("scope"), requestParameters.scope()), "The scope provided by the request-parameters should be provided as a query-parameter.");
            assertEquals(RESPONSE_TYPE_CODE, queryMap.get("response_type"), "The query should contain the correct response type.");
            return true;
        }))).thenReturn(CompletableFuture.completedFuture(authorizationRequest));
    }

    private void mockCredentialRepository(List<Credential> credentials) {
        // lenient, to work with parameterizations that might throw something before
        lenient().when(credentialsRepository.getCredentials()).thenReturn(credentials);
    }

    private void mockOpenIdConfiguration(Set<String> scopes, String verifierHost, String authorizationPath) {
        // the well-known response
        OpenIdConfiguration openIdConfiguration = new OpenIdConfiguration()
                .setAuthorizationEndpoint(URI.create("https://" + verifierHost + authorizationPath))
                .setTokenEndpoint(URI.create("https://" + verifierHost + "/token"))
                .setScopesSupported(scopes)
                .setGrantTypesSupported(Set.of(OIDConstants.VP_TOKEN_GRANT_TYPE))
                .setResponseTypesSupported(Set.of(OIDConstants.RESPONSE_TYPE_CODE));
        when(openIdConfigurationClient.getOpenIdConfiguration(any())).thenReturn(CompletableFuture.completedFuture(openIdConfiguration));
    }

    public static Stream<Arguments> provideRequestParameters() {
        return Stream.of(
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "", "test-client", Set.of("openid", "test")),
                        Set.of("openid", "test"),
                        Optional.of(getTypeQuery(false, List.of(List.of("MyCredential")))),
                        List.of(getSingleCredential(List.of("MyCredential"))),
                        List.of(getSingleCredential(List.of("MyCredential"))).stream().map(Credential::getRawCredential).map(CredentialBase::getRaw).toList()
                ),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("openid", "test")),
                        Set.of("openid", "test"),
                        Optional.of(getTypeQuery(false, List.of(List.of("MyCredential")))),
                        List.of(getSingleCredential(List.of("MyCredential"))),
                        List.of(getSingleCredential(List.of("MyCredential"))).stream().map(Credential::getRawCredential).map(CredentialBase::getRaw).toList()),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("test")),
                        Set.of("openid", "test", "none"),
                        Optional.of(getTypeQuery(false, List.of(List.of("MyCredential")))),
                        List.of(getSingleCredential(List.of("MyCredential"))),
                        List.of(getSingleCredential(List.of("MyCredential"))).stream().map(Credential::getRawCredential).map(CredentialBase::getRaw).toList()),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("test")),
                        Set.of("openid", "test", "none"),
                        Optional.of(getTypeQuery(false, List.of(List.of("MyCredential")))),
                        getMultipleCredentials(),
                        List.of(getSingleCredential(List.of("MyCredential"))).stream().map(Credential::getRawCredential).map(CredentialBase::getRaw).toList()),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("test")),
                        Set.of("openid", "test", "none"),
                        // we want multiple credentials returned
                        Optional.of(getTypeQuery(true, List.of(List.of("MyCredential"), List.of("DifferentType")))),
                        getMultipleCredentials(),
                        // from that list, all JWT_VC match
                        getMultipleCredentials().stream().filter(c -> c.getCredentialFormat() == CredentialFormat.JWT_VC_JSON).map(Credential::getRawCredential).map(CredentialBase::getRaw).toList()
                ),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("test")),
                        Set.of("openid", "test", "none"),
                        // we want multiple credentials returned
                        Optional.of(getCredentialSetQuery(true, List.of(List.of("MyCredential")))),
                        getMultipleCredentials(),
                        // from that list, the first jwt and the sd-matches. SDs are constructed with their disclosures,
                        // thus always have to end with ~
                        List.of("theCredential", "theSdCredential~")
                ),
                Arguments.of(
                        new RequestParameters(URI.create("test.io"), "/sub-path", "test-client", Set.of("test")),
                        Set.of("openid", "test", "none"),
                        // with no query, return everything
                        Optional.empty(),
                        List.of(getSingleCredential(List.of("MyCredential"))),
                        List.of("theCredential")
                )
        );
    }

    private static List<Credential> getMultipleCredentials() {
        return List.of(
                getSingleCredential(List.of("MyCredential")),
                getSingleSDCredential(),
                getSingleCredential(List.of("DifferentType"))
        );
    }

    private static Credential getSingleSDCredential() {
        return new Credential(CredentialFormat.VC_SD_JWT,
                new SdJwtCredential(
                        "theSdCredential",
                        new JwtCredential(
                                "theSdCredentialContent",
                                null,
                                Map.of("vc", Map.of(
                                        "type", List.of("MyCredential"),
                                        "issuer", "did:web:test-issuer.io",
                                        "credentialSubject", Map.of(
                                                "test", "claim"
                                        ))),
                                "sig"),
                        List.of())
        );
    }

    private static Credential getSingleCredential(List<String> type) {
        return
                new Credential(CredentialFormat.JWT_VC_JSON,
                        new JwtCredential(
                                "theCredential",
                                null,
                                Map.of("vc", Map.of(
                                        "type", type,
                                        "issuer", "did:web:test-issuer.io",
                                        "credentialSubject", Map.of(
                                                "test", "claim"
                                        ))),
                                "sig")
                );
    }

    private static DcqlQuery getFormatQuery(boolean multiple, CredentialFormat credentialFormat) {
        CredentialQuery credentialQuery = new CredentialQuery();
        credentialQuery.setFormat(credentialFormat);
        credentialQuery.setId("credential_query");
        credentialQuery.setMultiple(multiple);
        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credentialQuery));
        return dcqlQuery;
    }

    private static DcqlQuery getTypeQuery(boolean multiple, List<List<String>> queryType) {
        CredentialQuery credentialQuery = new CredentialQuery();
        credentialQuery.setFormat(CredentialFormat.JWT_VC_JSON);
        credentialQuery.setId("credential_query");
        credentialQuery.setMeta(Map.of("type_values", queryType));
        credentialQuery.setMultiple(multiple);
        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credentialQuery));
        return dcqlQuery;
    }

    private static DcqlQuery getInvalidQuery() {
        // set queries require the credential-query with the requested ID to be present -> invalid
        CredentialSetQuery credentialSetQueryTypes = new CredentialSetQuery();
        credentialSetQueryTypes.setRequired(true);
        credentialSetQueryTypes.setPurpose("test-types");
        credentialSetQueryTypes.setOptions(List.of(List.of("credential_query_types")));

        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentialSets(List.of(credentialSetQueryTypes));
        return dcqlQuery;
    }

    private static DcqlQuery getCredentialSetQuery(boolean multiple, List<List<String>> queryType) {
        CredentialSetQuery credentialSetQueryTypes = new CredentialSetQuery();
        credentialSetQueryTypes.setRequired(true);
        credentialSetQueryTypes.setPurpose("test-types");
        credentialSetQueryTypes.setOptions(List.of(List.of("credential_query_types")));

        CredentialSetQuery credentialSetQuerySd = new CredentialSetQuery();
        credentialSetQuerySd.setRequired(true);
        credentialSetQuerySd.setPurpose("test-sd");
        credentialSetQuerySd.setOptions(List.of(List.of("credential_query_sd")));

        CredentialQuery credentialQueryType = new CredentialQuery();
        credentialQueryType.setFormat(CredentialFormat.JWT_VC_JSON);
        credentialQueryType.setId("credential_query_types");
        credentialQueryType.setMeta(Map.of("type_values", queryType));
        credentialQueryType.setMultiple(multiple);

        CredentialQuery credentialQuerySd = new CredentialQuery();
        credentialQuerySd.setFormat(CredentialFormat.VC_SD_JWT);
        credentialQuerySd.setId("credential_query_sd");
        credentialQuerySd.setMultiple(multiple);

        DcqlQuery dcqlQuery = new DcqlQuery();
        dcqlQuery.setCredentials(List.of(credentialQueryType, credentialQuerySd));
        dcqlQuery.setCredentialSets(List.of(credentialSetQueryTypes, credentialSetQuerySd));
        return dcqlQuery;
    }


    private boolean compareScope(String scopeString, Set<String> scopes) {
        return new HashSet<>(Arrays.asList(scopeString.split("\\+"))).equals(scopes);
    }

    public Map<String, String> fromData(String data) {
        Map<String, String> dataMap = new HashMap<>();
        String[] queryParts = data.split("&");
        Arrays.stream(queryParts)
                .forEach(part -> {
                    String[] partParts = part.split("=");
                    dataMap.put(partParts[0], partParts[1]);
                });
        return dataMap;
    }
}
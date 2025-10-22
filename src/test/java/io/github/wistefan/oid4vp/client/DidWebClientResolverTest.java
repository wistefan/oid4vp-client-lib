package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.jwk.*;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.TestHelpers;
import io.github.wistefan.oid4vp.exception.BadGatewayException;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpResponse;
import java.security.PublicKey;
import java.security.Security;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECPoint;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionException;
import java.util.concurrent.ExecutionException;
import java.util.function.BiFunction;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;

@ExtendWith(MockitoExtension.class)
public class DidWebClientResolverTest extends ClientResolverTest {

    private static final TestHelpers TEST_HELPERS = new TestHelpers();

    @Mock
    private HttpClient httpClient;

    private DidWebClientResolver didWebClientResolver;
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @BeforeAll
    public static void addBouncyCastler() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setUp() {
        didWebClientResolver = new DidWebClientResolver(httpClient, OBJECT_MAPPER);
    }

    @DisplayName("did:web should be correctly identified.")
    @ParameterizedTest
    @ValueSource(strings = {"did:web:test.org", "did:web:test.org:user:alice"})
    public void testIsSupported(String clientId) {
        assertTrue(didWebClientResolver.isSupportedId(clientId), "The given id should be supported.");
    }

    @DisplayName("Only did:web should be supported.")
    @ParameterizedTest
    @ValueSource(strings = {"did:jwk:eISomething", "x509_san_dns:test.io", "z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "key:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "did:key:z6MknyInvalid", "did:key:something-invalid", "did:web", "web:something.org", "something.org"})
    public void testIsNotSupported(String clientId) {
        assertFalse(didWebClientResolver.isSupportedId(clientId), "The given id should not be supported.");
    }

    @DisplayName("The public key should be retrieved from the did:web.")
    @ParameterizedTest
    @MethodSource("provideValidDidWeb")
    public void testGetPublicKey(String clientId, String keyId, String expectedWellKnown, PublicKey expectedKey, DidDocument didDocument) throws Exception {
        SignedJWT signedJWT = prepareMock(keyId, expectedWellKnown, 200, didDocument);

        PublicKey resolvedKey = didWebClientResolver.getPublicKey(clientId, signedJWT).get();

        switch (expectedKey.getAlgorithm()) {
            case "RSA" ->
                    assertEquals(resolvedKey, expectedKey, "The correct key should have been resolved from the did web.");
            case "EC" -> assertEcKeysEqual(expectedKey, resolvedKey);
            case "EdDSA" -> assertEdEcEquals(expectedKey, resolvedKey);
            default -> fail(String.format("KeyType %s is not supported.", expectedKey.getAlgorithm()));
        }
    }

    @DisplayName("An error should be thrown, if no valid key can be retrieved.")
    @ParameterizedTest(name = "{index} - {6}")
    @MethodSource("provideClientErrors")
    public void testGetPublicKeyError(String clientId, String keyId, String wellKnown, int statusCode, DidDocument didDocument, Class<? extends RuntimeException> expectedException, String message) {
        SignedJWT signedJWT = prepareMock(keyId, wellKnown, statusCode, didDocument);
        assertThrows(expectedException, () -> TEST_HELPERS.executeWithUnwrapping(clientId, signedJWT, (a, b) -> didWebClientResolver.getPublicKey(a, b)), message);
    }

    private static Map<String, Object> remove(Map<String, Object> theMap, String key) {
        theMap.remove(key);
        return theMap;
    }

    private static Map<String, Object> replace(Map<String, Object> theMap, String key, Object value) {
        theMap.replace(key, value);
        return theMap;
    }

    private static Stream<Arguments> provideClientErrors() throws Exception {
        Map<String, Object> rsaJWK = rsaPublicKeyToJWK((RSAPublicKey) getRSAKey().getPublic()).toJSONObject();
        Map<String, Object> ecJWK = ecPublicKeyToJWK((ECPublicKey) getECKey().getPublic()).toJSONObject();
        Map<String, Object> ed25519JWK = ed255519PublicKeyToJWK(getED25519Key().getPublic()).toJSONObject();


        return Stream.of(
                Arguments.of("did:key:test.io", "myKey", "", 0, null, ClientResolutionException.class,
                        "Unsupported did-methods should be rejected."),
                Arguments.of("x509_san_dns:test.io", "myKey", "", 0, null, ClientResolutionException.class,
                        "Unsupported client ids should be rejected."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 400,
                        null,
                        BadGatewayException.class,
                        "If the target server does not properly respond, a BadGateway should be indicated."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:some-other.id"),
                        ClientResolutionException.class,
                        "If the did-document is invalid, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        null,
                        ClientResolutionException.class,
                        "If the did-document is invalid, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(null),
                        ClientResolutionException.class,
                        "If the did-document does not contain a verification method, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of()),
                        ClientResolutionException.class,
                        "If the did-document does not contain a verification method, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("otherKey")
                        )),
                        ClientResolutionException.class,
                        "If the did-document does not contain a verification method with the requested key, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                        )),
                        ClientResolutionException.class,
                        "If the verification method does not contain a jwk, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(replace(rsaJWK, "use", "enc"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk is not for signatures, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(remove(rsaJWK, "use"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk does not contain the required parameters, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(remove(rsaJWK, "alg"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk does not contain the required parameters, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(replace(ed25519JWK, "x", "invalidValue"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk contains invalid parameters, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(replace(ecJWK, "x", "invalidValue"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk contains invalid parameters, a ClientResolutionException should be returned."),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", 200,
                        new DidDocument().setId("did:web:test.io").setVerificationMethod(List.of(
                                new VerificationMethod().setId("myKey")
                                        .setPublicKeyJwk(replace(ecJWK, "crv", "SOMETHING-WEIRD"))
                        )),
                        ClientResolutionException.class,
                        "If the jwk contains invalid parameters, a ClientResolutionException should be returned.")
        );
    }

    private static Stream<Arguments> provideValidDidWeb() throws Exception {
        PublicKey rsaKey = getRSAKey().getPublic();
        PublicKey ecKey = getECKey().getPublic();
        PublicKey ed25519Key = getED25519Key().getPublic();
        return Stream.of(
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", rsaKey, new DidDocument()
                        .setId("did:web:test.io")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("myKey")
                                        .setPublicKeyJwk(toJWK(rsaKey, KeyType.RSA).toJSONObject())))),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", ecKey, new DidDocument()
                        .setId("did:web:test.io")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("myKey")
                                        .setPublicKeyJwk(toJWK(ecKey, KeyType.EC).toJSONObject())))),
                Arguments.of("did:web:test.io", "myKey", "https://test.io/.well-known/did.json", ed25519Key, new DidDocument()
                        .setId("did:web:test.io")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("myKey")
                                        .setPublicKeyJwk(toJWK(ed25519Key, KeyType.ED25519).toJSONObject())))),
                Arguments.of("did:web:test.io", "#myRsaKey", "https://test.io/.well-known/did.json", rsaKey, new DidDocument()
                        .setId("did:web:test.io")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("#myRsaKey")
                                        .setPublicKeyJwk(toJWK(rsaKey, KeyType.RSA).toJSONObject()),
                                new VerificationMethod()
                                        .setId("#myECKey")
                                        .setPublicKeyJwk(toJWK(ecKey, KeyType.EC).toJSONObject()),
                                new VerificationMethod()
                                        .setId("#myEDKey")
                                        .setPublicKeyJwk(toJWK(ed25519Key, KeyType.ED25519).toJSONObject())
                        ))),
                Arguments.of("did:web:test.io:somewhere:down", "#myRsaKey", "https://test.io/somewhere/down/did.json", rsaKey, new DidDocument()
                        .setId("did:web:test.io:somewhere:down")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("#myRsaKey")
                                        .setPublicKeyJwk(toJWK(rsaKey, KeyType.RSA).toJSONObject()),
                                new VerificationMethod()
                                        .setId("#myECKey")
                                        .setPublicKeyJwk(toJWK(ecKey, KeyType.EC).toJSONObject()),
                                new VerificationMethod()
                                        .setId("#myEDKey")
                                        .setPublicKeyJwk(toJWK(ed25519Key, KeyType.ED25519).toJSONObject())
                        ))),
                Arguments.of("did:web:test.io:somewhere:down", "did:web:test.io:somewhere:down#myECKey", "https://test.io/somewhere/down/did.json", ecKey, new DidDocument()
                        .setId("did:web:test.io:somewhere:down")
                        .setVerificationMethod(List.of(
                                new VerificationMethod()
                                        .setId("#myRsaKey")
                                        .setPublicKeyJwk(toJWK(rsaKey, KeyType.RSA).toJSONObject()),
                                new VerificationMethod()
                                        .setId("did:web:test.io:somewhere:down#myECKey")
                                        .setPublicKeyJwk(toJWK(ecKey, KeyType.EC).toJSONObject()),
                                new VerificationMethod()
                                        .setId("#myEDKey")
                                        .setPublicKeyJwk(toJWK(ed25519Key, KeyType.ED25519).toJSONObject())
                        )))
        );
    }

    private SignedJWT prepareMock(String keyId, String expectedWellKnown, int statusCode, DidDocument didDocument) {
        // create the mocks lenient, to prevent UnnecessaryStubbingException in parameterized case
        JWSHeader jwsHeader = mock(JWSHeader.class);
        lenient().when(jwsHeader.getKeyID()).thenReturn(keyId);
        SignedJWT signedJWT = mock(SignedJWT.class);
        lenient().when(signedJWT.getHeader()).thenReturn(jwsHeader);
        HttpResponse<DidDocument> mockResponse = mock(HttpResponse.class);
        lenient().when(mockResponse.statusCode()).thenReturn(statusCode);
        lenient().when(mockResponse.body()).thenReturn(didDocument);
        lenient().when(httpClient.sendAsync(
                        argThat(req -> req.uri().toString().equals(expectedWellKnown)),
                        any(HttpResponse.BodyHandler.class)))
                .thenReturn(CompletableFuture.completedFuture(mockResponse));
        return signedJWT;
    }

    private static JWK toJWK(PublicKey publicKey, KeyType keyType) throws JOSEException {
        return switch (keyType) {
            case EC -> ecPublicKeyToJWK((ECPublicKey) publicKey);
            case RSA -> rsaPublicKeyToJWK((RSAPublicKey) publicKey);
            case ED25519 -> ed255519PublicKeyToJWK(publicKey);
        };
    }

    private static OctetKeyPair ed255519PublicKeyToJWK(PublicKey publicKey) throws JOSEException {
        byte[] encoded = publicKey.getEncoded();
        byte[] raw = Arrays.copyOfRange(encoded, encoded.length - 32, encoded.length);
        return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(raw))
                .keyUse(KeyUse.SIGNATURE)
                .keyIDFromThumbprint()
                .build();
    }

    private static RSAKey rsaPublicKeyToJWK(RSAPublicKey publicKey) throws JOSEException {
        return new RSAKey.Builder(publicKey)
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.RS256)
                .keyIDFromThumbprint()
                .build();
    }

    private static ECKey ecPublicKeyToJWK(ECPublicKey pub) throws JOSEException {
        ECPoint w = pub.getW();
        Curve curve = Curve.P_256;

        byte[] xBytes = toUnsignedBytes(w.getAffineX(), 32);
        byte[] yBytes = toUnsignedBytes(w.getAffineY(), 32);

        return new ECKey.Builder(curve, Base64URL.encode(xBytes), Base64URL.encode(yBytes))
                .keyUse(KeyUse.SIGNATURE)
                .algorithm(JWSAlgorithm.ES256)
                .keyIDFromThumbprint()
                .build();
    }

    private static byte[] toUnsignedBytes(BigInteger b, int size) {
        byte[] raw = b.toByteArray();
        if (raw.length == size) return raw;
        if (raw.length == size + 1 && raw[0] == 0) return Arrays.copyOfRange(raw, 1, raw.length);
        // pad with leading zeros
        byte[] padded = new byte[size];
        System.arraycopy(raw, 0, padded, size - raw.length, raw.length);
        return padded;
    }

    private enum KeyType {
        RSA,
        EC,
        ED25519
    }
}
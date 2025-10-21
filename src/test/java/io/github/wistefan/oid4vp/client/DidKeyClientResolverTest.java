package io.github.wistefan.oid4vp.client;

import io.github.wistefan.oid4vp.OID4VPClientIT;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.KeyType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DidKeyClientResolverTest extends ClientResolverTest {

    private ClientResolver clientResolver;

    @BeforeAll
    public static void setupBC() {
        Security.addProvider(new BouncyCastleProvider());
    }

    @BeforeEach
    public void setup() {
        clientResolver = new DidKeyClientResolver();
    }

    public static Stream<Arguments> getTestDids() {
        return Stream.of(
                Arguments.of("did:key:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", KeyType.ED_25519, "test-keys/z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE.pem"),
                Arguments.of("did:key:z6MkuzKwyYDhvGFwixztjJTbBgZi2C5kBxJ3ick1MxWmXJ8T", KeyType.ED_25519, "test-keys/z6MkuzKwyYDhvGFwixztjJTbBgZi2C5kBxJ3ick1MxWmXJ8T.pem"),
                Arguments.of("did:key:z6MkhVs9z75LtxHCMGjEjPMfmBKrgMENR3zYwTc5g2o9H6Vt", KeyType.ED_25519, "test-keys/z6MkhVs9z75LtxHCMGjEjPMfmBKrgMENR3zYwTc5g2o9H6Vt.pem"),
                Arguments.of("did:key:zDnaeYeUQQGPqbPFVoU93HuvX5XLeppmENvx3fCcmApUdPttJ", KeyType.P_256, "test-keys/zDnaeYeUQQGPqbPFVoU93HuvX5XLeppmENvx3fCcmApUdPttJ.pem"),
                Arguments.of("did:key:zDnaebD3Z6db24oMAXNXjQLMknVnt1AeSWEiRxhNZBMFpBtAh", KeyType.P_256, "test-keys/zDnaebD3Z6db24oMAXNXjQLMknVnt1AeSWEiRxhNZBMFpBtAh.pem"),
                Arguments.of("did:key:zDnaeVTkZ2fKNXWfNquyCe2oZuNA313bLwPcqdozfJ4sxC1e3", KeyType.P_256, "test-keys/zDnaeVTkZ2fKNXWfNquyCe2oZuNA313bLwPcqdozfJ4sxC1e3.pem"),
                Arguments.of("did:key:z82LksDNeAsaYGymiJEAsCgR6wj8JEcvJkdLu24DwDnLGkpBmUL2GQeGnDA1FsVbRrRpMK2", KeyType.P_384, "test-keys/z82LksDNeAsaYGymiJEAsCgR6wj8JEcvJkdLu24DwDnLGkpBmUL2GQeGnDA1FsVbRrRpMK2.pem"),
                Arguments.of("did:key:z82Lm4a86fagXYdhES9aLpwpuw8jiVPWks5eQLJt8NhARHDUsNFgCjgs997QPqbdKGLzZ4F", KeyType.P_384, "test-keys/z82Lm4a86fagXYdhES9aLpwpuw8jiVPWks5eQLJt8NhARHDUsNFgCjgs997QPqbdKGLzZ4F.pem"),
                Arguments.of("did:key:z82LkukkxhxLUSD5WpmWtdNvnwHEJ4HQySqAediKworJwtcyCStFxRPobg8PGrxfkdKXBMs", KeyType.P_384, "test-keys/z82LkukkxhxLUSD5WpmWtdNvnwHEJ4HQySqAediKworJwtcyCStFxRPobg8PGrxfkdKXBMs.pem")
        );
    }

    @DisplayName("did:key should be correctly identified.")
    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testIsSupported(String clientId) {
        assertTrue(clientResolver.isSupportedId(clientId), "The client is a did:key.");
    }

    @DisplayName("The key-type should be correctly retrieved from the did:key identifier part.")
    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testGetKeyType(String clientId, KeyType keyType) {
        assertEquals(keyType, KeyType.fromKey(clientId.replaceFirst("did:key:", "")), "The correct key-type should have been retrieved.");
    }

    @DisplayName("Only did:key should be supported.")
    @ParameterizedTest
    @ValueSource(strings = {"did:web:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "did:jwk:eISomething", "x509_san_dns:test.io", "z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "key:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE"})
    public void testIsNotSuppored(String clientId) {
        assertFalse(clientResolver.isSupportedId(clientId), "Invalid clientIds should not be supported.");
    }

    @DisplayName("An error should be thrown, if no valid key can be retrieved.")
    @ParameterizedTest
    @ValueSource(strings = {"non-did:web:test.io", "did:jwk:eISomething", "x509_san_dns:test.io", "clientId", "did:key:z6MknyInvalid", "did:key:something-invalid"})
    public void testGetPublicKeyError(String clientId) {
        assertThrows(ClientResolutionException.class, () -> clientResolver.getPublicKey(clientId, null), "Invalid inputs should return a ClientResolutinException.");
    }

    @DisplayName("The public key should be retrieved from the did:key.")
    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testGetPublicKey(String clientId, KeyType keyType, String expectedKeyPath) throws Exception {
        PublicKey expectedPublicKey = loadPublicKey(expectedKeyPath, keyType);
        PublicKey resolvedKey = clientResolver.getPublicKey(clientId, null).get();

        switch (keyType) {
            case P_256, P_384 -> assertEcKeysEqual(expectedPublicKey, resolvedKey);
            case ED_25519 -> assertEdEcEquals(expectedPublicKey, resolvedKey);

        }
    }


    private static PublicKey loadPublicKey(String pemFile, KeyType keyType) throws Exception {
        try (InputStream is = OID4VPClientIT.class.getClassLoader().getResourceAsStream(pemFile)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + pemFile);
            }

            String pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);

            // Remove header/footer and whitespace
            String base64 = pem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replace("-----END PUBLIC KEY-----", "")
                    .replaceAll("\\s+", "");

            byte[] der = Base64.getDecoder().decode(base64);

            X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
            KeyFactory kf = getKeyFactoryForKeyType(keyType);
            return kf.generatePublic(spec);
        }
    }

    private static KeyFactory getKeyFactoryForKeyType(KeyType keyType) throws NoSuchAlgorithmException, NoSuchProviderException {
        return switch (keyType) {
            case ED_25519 -> KeyFactory.getInstance("Ed25519");
            case P_256 -> KeyFactory.getInstance("EC");
            case P_384 -> KeyFactory.getInstance("EC");
        };
    }

}
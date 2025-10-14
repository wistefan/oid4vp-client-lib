package io.github.wistefan.oid4vp;

import io.github.wistefan.oid4vp.client.ClientResolver;
import io.github.wistefan.oid4vp.client.DidKeyClientResolver;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.KeyType;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;
import java.util.Base64;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

class DidKeyClientResolverTest {

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

    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testIsSupported(String clientId, KeyType keyType, String expectedKeyPath) {
        assertTrue(clientResolver.isSupportedId(clientId), "The client is a did:key.");
    }

    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testGetKeyType(String clientId, KeyType keyType, String expectedKeyPath) {
        assertEquals(keyType, KeyType.fromKey(clientId.replaceFirst("did:key:", "")), "The correct key-type should have been retrieved.");
    }

    @ParameterizedTest
    @ValueSource(strings = {"did:web:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "did:jwk:eISomething", "x509_san_dns:test.io", "z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "key:z6MknYNDRL2s1KhzfoPM7PJmH56XmfuAPnMu2AFTEXbouvXE", "did:key:z6MknyInvalid", "did:key:something-invalid"})
    public void testIsNotSuppored(String clientId) {
        assertThrows(ClientResolutionException.class, () -> clientResolver.getPublicKey(clientId, null), "Invalid inputs should return a ClientResolutinException.");
    }

    @ParameterizedTest
    @ValueSource(strings = {"non-did:web:test.io", "did:jwk:eISomething", "x509_san_dns:test.io", "clientId"})
    public void testGetPublicKeyError(String clientId) {

    }

    @ParameterizedTest
    @MethodSource("getTestDids")
    public void testGetPublicKey(String clientId, KeyType keyType, String expectedKeyPath) throws Exception {
        PublicKey expectedPublicKey = loadPublicKey(expectedKeyPath, keyType);
        PublicKey resolvedKey = clientResolver.getPublicKey(clientId, null).get();

        switch (keyType) {
            case P_256, P_384 ->
                    assertTrue(ecKeysEqual(expectedPublicKey, resolvedKey), "The public key should be correctly resolved.");
            case ED_25519 -> {
                assertEdEcEquals(expectedPublicKey, resolvedKey);
            }
        }
    }


    private static PublicKey loadPublicKey(String pemFile, KeyType keyType) throws Exception {
        try (InputStream is = ClientTest.class.getClassLoader().getResourceAsStream(pemFile)) {
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

    private static void assertEdEcEquals(PublicKey pk1, PublicKey pk2) {
        if (pk1 instanceof EdECPublicKey k1 && pk2 instanceof EdECPublicKey k2) {
            NamedParameterSpec spec1 = k1.getParams();
            NamedParameterSpec spec2 = k2.getParams();
            assertEquals(spec1.getName(), spec2.getName());
            EdECPoint point1 = k1.getPoint();
            EdECPoint point2 = k2.getPoint();
            assertEquals(point1.isXOdd(), point2.isXOdd(), "XOdd needs to be equal");
            assertEquals(point1.getY(), point2.getY(), "Both points should have the same y param.");
        } else {
            fail("Did not receive EdECPublicKeys");
        }
    }

    public static boolean ecKeysEqual(PublicKey k1, PublicKey k2) {
        if (!(k1 instanceof ECPublicKey) || !(k2 instanceof ECPublicKey)) return false;

        ECPublicKey ec1 = (ECPublicKey) k1;
        ECPublicKey ec2 = (ECPublicKey) k2;

        ECPoint p1 = ec1.getW();
        ECPoint p2 = ec2.getW();

        ECParameterSpec spec1 = ec1.getParams();
        ECParameterSpec spec2 = ec2.getParams();

        // Compare X and Y coordinates
        boolean pointEquals = p1.getAffineX().equals(p2.getAffineX()) &&
                p1.getAffineY().equals(p2.getAffineY());

        // Compare curve parameters
        boolean curveEquals = spec1.getCurve().getA().equals(spec2.getCurve().getA()) &&
                spec1.getCurve().getB().equals(spec2.getCurve().getB()) &&
                spec1.getCurve().getField().getFieldSize() == spec2.getCurve().getField().getFieldSize();

        return pointEquals && curveEquals;
    }

}
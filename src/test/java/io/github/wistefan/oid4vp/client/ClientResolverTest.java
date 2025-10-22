package io.github.wistefan.oid4vp.client;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.EdECPublicKey;
import java.security.spec.*;

import static org.junit.jupiter.api.Assertions.*;

public abstract class ClientResolverTest {

    public static void assertEdEcEquals(PublicKey pk1, PublicKey pk2) {
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

    public static void assertEcKeysEqual(PublicKey k1, PublicKey k2) {
        if (k1 instanceof ECPublicKey ec1 && k2 instanceof ECPublicKey ec2) {

            ECPoint p1 = ec1.getW();
            ECPoint p2 = ec2.getW();

            ECParameterSpec spec1 = ec1.getParams();
            ECParameterSpec spec2 = ec2.getParams();

            // use compareTo to compare numerical and ignore potential encoding fragments like leading zeros
            boolean pointEquals =
                    p1.getAffineX().compareTo(p2.getAffineX()) == 0 &&
                            p1.getAffineY().compareTo(p2.getAffineY()) == 0;
            assertTrue(pointEquals, "The points of the keys need to be numerical equal.");

            // Compare curve parameters
            boolean curveEquals = spec1.getCurve().getA().equals(spec2.getCurve().getA()) &&
                    spec1.getCurve().getB().equals(spec2.getCurve().getB()) &&
                    spec1.getCurve().getField().getFieldSize() == spec2.getCurve().getField().getFieldSize();
            assertTrue(curveEquals, "Both keys need to use the same curve.");
        } else {
            fail("Both keys should be of type ECPublicKey.");
        }
    }

    public static KeyPair getRSAKey() throws Exception {
        return getRSAKey(2048);
    }

    public static KeyPair getRSAKey(int keySize) throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair getECKey() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EC");
        keyPairGenerator.initialize(new ECGenParameterSpec("secp256r1"));
        return keyPairGenerator.generateKeyPair();
    }

    public static KeyPair getED25519Key() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519");
        return keyPairGenerator.generateKeyPair();
    }

}

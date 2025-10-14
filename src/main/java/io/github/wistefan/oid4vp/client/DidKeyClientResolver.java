package io.github.wistefan.oid4vp.client;

import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import io.github.wistefan.oid4vp.model.KeyType;
import org.bitcoinj.base.Base58;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.util.SubjectPublicKeyInfoFactory;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.math.ec.ECPoint;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.concurrent.CompletableFuture;

/**
 * Implementation to support did:key{@see https://w3c-ccg.github.io/did-key-spec} resolution.
 */
public class DidKeyClientResolver implements ClientResolver {

    private static final String DID_KEY_PREFIX = "did:key:";
    private static final String MULTIBASE_PREFIX = "z";


    @Override
    public boolean isSupportedId(String clientId) {
        return clientId != null && clientId.startsWith(DID_KEY_PREFIX);
    }


    @Override
    public CompletableFuture<PublicKey> getPublicKey(String clientId, SignedJWT jwt) {
        if (!isSupportedId(clientId)) {
            throw new ClientResolutionException(String.format("The client %s is not a supported type.", clientId));
        }
        String keyPart = clientId.replaceFirst(DID_KEY_PREFIX, "");
        KeyType type = KeyType.fromKey(keyPart);

        // remove the multibase prefix to have a clean key
        String removedPrefix = keyPart.replaceFirst(MULTIBASE_PREFIX, "");
        byte[] decoded;
        try {
            decoded = Base58.decode(removedPrefix);
        } catch (RuntimeException e) {
            throw new ClientResolutionException("Was not able to decode the raw key.", e);
        }
        try (ByteArrayInputStream in = new ByteArrayInputStream(decoded)) {
            // the type indicator needs to be consumed to get the plain key
            readVarint(in);
            // create the key from the plain bytes
            return CompletableFuture.supplyAsync(() -> {
                try {
                    return createPublicKey(type, in.readAllBytes());
                } catch (GeneralSecurityException e) {
                    throw new ClientResolutionException("Failed to create public key", e);
                }
            });
        } catch (IOException e) {
            throw new ClientResolutionException("Failed to decode public key", e);
        }
    }

    // function to consume and return the type indicator bytes
    private static int readVarint(ByteArrayInputStream in) {
        int value = 0;
        int shift = 0;
        int b;
        while (((b = in.read()) != -1)) {
            value |= (b & 0x7F) << shift;

            if ((b & 0x80) == 0) break;
            // last byte
            shift += 7;
            if (shift > 35) throw new ClientResolutionException("VarInt of the key is too long");
        }
        return value;
    }

    private static PublicKey createPublicKey(KeyType keyType, byte[] rawBytes) throws GeneralSecurityException {
        switch (keyType) {
            case ED_25519:
                return createEd25519PublicKey(rawBytes);

            case P_256:
                return createEcPublicKey(rawBytes, "secp256r1"); // aka prime256v1

            case P_384:
                return createEcPublicKey(rawBytes, "secp384r1");

            default:
                throw new ClientResolutionException("Unsupported multicodec value: " + keyType);
        }
    }

    private static PublicKey createEcPublicKey(byte[] rawBytes, String curveName) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("EC");

        // X.509 SPKI wrapping (similar to secp256k1 case but with proper OID for curve)
        EncodedKeySpec keySpec = new X509EncodedKeySpec(wrapEcInX509(rawBytes, curveName));
        return kf.generatePublic(keySpec);
    }

    private static byte[] wrapEcInX509(byte[] rawBytes, String curveName) throws GeneralSecurityException {
        // Use BouncyCastle to generate proper SPKI for curve
        AlgorithmParameters params = AlgorithmParameters.getInstance("EC");
        params.init(new ECGenParameterSpec(curveName));

        org.bouncycastle.jce.spec.ECParameterSpec bcSpec = ECNamedCurveTable.getParameterSpec(curveName);
        ECPoint ecPoint = bcSpec.getCurve().decodePoint(rawBytes);

        try {
            ECDomainParameters domainParams = new ECDomainParameters(
                    bcSpec.getCurve(),
                    bcSpec.getG(),
                    bcSpec.getN(),
                    bcSpec.getH()
            );

            AsymmetricKeyParameter pubKeyParams = new ECPublicKeyParameters(ecPoint, domainParams);

            return SubjectPublicKeyInfoFactory
                    .createSubjectPublicKeyInfo(pubKeyParams)
                    .getEncoded();
        } catch (Exception e) {
            throw new GeneralSecurityException("Failed to wrap EC key in X.509", e);
        }
    }

    private static PublicKey createEd25519PublicKey(byte[] rawBytes) throws GeneralSecurityException {
        KeyFactory kf = KeyFactory.getInstance("Ed25519");
        EncodedKeySpec keySpec = new X509EncodedKeySpec(wrapEd25519InX509(rawBytes));
        return kf.generatePublic(keySpec);
    }

    /**
     * Wraps raw Ed25519 32-byte key into an X.509 SubjectPublicKeyInfo structure (RFC 8410).
     */
    private static byte[] wrapEd25519InX509(byte[] rawBytes) {
        byte[] prefix = new byte[]{
                0x30, 0x2a,                         // SEQUENCE, length 42
                0x30, 0x05,                         // SEQUENCE, length 5
                0x06, 0x03, 0x2b, 0x65, 0x70,       // OID 1.3.101.112 (Ed25519)
                0x03, 0x21, 0x00                    // BIT STRING, length 33, unused bits = 0
        };
        byte[] result = new byte[prefix.length + rawBytes.length];
        System.arraycopy(prefix, 0, result, 0, prefix.length);
        System.arraycopy(rawBytes, 0, result, prefix.length, rawBytes.length);
        return result;
    }

}
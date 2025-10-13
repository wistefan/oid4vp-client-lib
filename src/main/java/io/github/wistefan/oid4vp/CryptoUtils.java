package io.github.wistefan.oid4vp;

import com.nimbusds.jose.JWSAlgorithm;

import java.security.Key;
import java.security.SecureRandom;
import java.security.interfaces.*;
import java.util.Base64;
import java.util.Optional;

/**
 * Helper class to for certain crypto functions
 */
public abstract class CryptoUtils {

    private static final SecureRandom secureRandom = new SecureRandom();
    private static final Base64.Encoder base64Encoder = Base64.getUrlEncoder().withoutPadding();

    /**
     * Generates a random string of the given byte-length
     */
    public static String generateRandomString(int byteLength) {
        byte[] randomBytes = new byte[byteLength];
        secureRandom.nextBytes(randomBytes);
        return base64Encoder.encodeToString(randomBytes);
    }

    /**
     * Extracts the corresponding {@link JWSAlgorithm} from the given key.
     */
    public static Optional<JWSAlgorithm> getAlgorithmForKey(Key key) {

        if (key instanceof RSAPrivateKey privateKey) {
            int modulusLength = privateKey.getModulus().bitLength();

            // Map modulus length to algorithm — conservative defaults
            if (modulusLength >= 4096) {
                return Optional.of(JWSAlgorithm.RS512);
            } else if (modulusLength >= 3072) {
                return Optional.of(JWSAlgorithm.RS384);
            } else {
                return Optional.of(JWSAlgorithm.RS256);
            }
        }
        if (key instanceof ECPrivateKey privateKey) {
            int fieldSize = privateKey.getParams().getCurve().getField().getFieldSize();
            if (fieldSize <= 256) return Optional.of(JWSAlgorithm.ES256);
            if (fieldSize <= 384) return Optional.of(JWSAlgorithm.ES384);
            return Optional.of(JWSAlgorithm.ES512);
        }
        return Optional.empty();
    }
}

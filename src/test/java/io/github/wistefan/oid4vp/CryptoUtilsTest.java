package io.github.wistefan.oid4vp;

import com.nimbusds.jose.JWSAlgorithm;
import io.github.wistefan.oid4vp.client.ClientResolverTest;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.security.Key;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CryptoUtilsTest {

    @DisplayName("The algorithm should be retrieved from the key.")
    @ParameterizedTest(name = "{index} - {2}")
    @MethodSource("provideValidKeys")
    public void testGetAlgorithmForKey(Key key, JWSAlgorithm expecteAlgorithm, String message) {
        assertEquals(CryptoUtils.getAlgorithmForKey(key).get(), expecteAlgorithm, message);
    }

    @DisplayName("For unsupported or invalid keys, an error should be thrown.")
    @Test
    public void testGetAlgorithmForKeyError() throws Exception {
        assertTrue(CryptoUtils.getAlgorithmForKey(ClientResolverTest.getED25519Key().getPrivate()).isEmpty(), "If the key is not of a supported type, empty should be returned.");
    }

    public static Stream<Arguments> provideValidKeys() throws Exception {
        return Stream.of(
                Arguments.of(ClientResolverTest.getRSAKey(2048).getPrivate(), JWSAlgorithm.RS256, "The algorithm should be identified as RS256."),
                Arguments.of(ClientResolverTest.getRSAKey(3072).getPrivate(), JWSAlgorithm.RS384, "The algorithm should be identified as RS384."),
                Arguments.of(ClientResolverTest.getRSAKey(4096).getPrivate(), JWSAlgorithm.RS512, "The algorithm should be identified as RS512."),
                Arguments.of(ClientResolverTest.getECKey().getPrivate(), JWSAlgorithm.ES256, "The algorithm should be identified as ES256.")
        );
    }

}
package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWEAlgorithm;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.client.ClientResolverTest;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.model.VerifiablePresentation;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import java.net.URI;
import java.security.KeyPair;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.text.ParseException;
import java.util.List;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

public class HolderSigningServiceTest {

    private ObjectMapper objectMapper;

    @BeforeEach
    public void setUp() {
        objectMapper = new ObjectMapper();
    }

    @DisplayName("Verifiable Presentations should properly be signed.")
    @ParameterizedTest
    @MethodSource("provideValidSigningVPs")
    public void testSignPresentation(HolderConfiguration holderConfiguration, VerifiablePresentation vp, JWSVerifier verifier) throws ParseException, JOSEException {
        HolderSigningService holderSigningService = new HolderSigningService(holderConfiguration, objectMapper);
        String jwt = holderSigningService.signPresentation(vp);

        SignedJWT theJwt = SignedJWT.parse(jwt);
        assertTrue(theJwt.verify(verifier), "The token should contain a valid signature.");
        assertEquals(holderConfiguration.kid(), theJwt.getHeader().getKeyID(), "The kid should be set correctly in the jwt header.");
        assertEquals(JOSEObjectType.JWT, theJwt.getHeader().getType(), "The correct typ header should be set.");
        assertEquals(holderConfiguration.holderId().toString(), theJwt.getJWTClaimsSet().getIssuer(), "The correct issuer should be set.");

        VerifiablePresentation payload = objectMapper.convertValue(theJwt.getJWTClaimsSet().getClaim("vp"), VerifiablePresentation.class);
        assertEquals(vp, payload, "The contained payload should be the provided presentation.");
    }

    @DisplayName("With invalid configurations, the presentation should not be signed.")
    @ParameterizedTest(name = "{index} - {1}")
    @MethodSource("provideInvalidHolderConfiguration")
    public void testInvalidConfiguration(HolderConfiguration holderConfiguration, String message) {
        assertThrows(AuthorizationException.class, () -> new HolderSigningService(holderConfiguration, objectMapper), message);
    }

    private static Stream<Arguments> provideInvalidHolderConfiguration() throws Exception {
        KeyPair rsaKeyPair = ClientResolverTest.getRSAKey();
        KeyPair ecKeyPair = ClientResolverTest.getECKey();
        KeyPair ed25519KeyPair = ClientResolverTest.getED25519Key();

        return Stream.of(
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.ECDH_ES, rsaKeyPair.getPrivate()),
                        "The algorithm needs to work with the key."),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.RSA_OAEP_512, ecKeyPair.getPrivate()),
                        "The algorithm needs to work with the key."),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.PBES2_HS256_A128KW, ed25519KeyPair.getPrivate()),
                        "The signing service should only be created for supported algorithms.")
        );
    }

    private static Stream<Arguments> provideValidSigningVPs() throws Exception {
        KeyPair rsa256KeyPair = ClientResolverTest.getRSAKey(2048);
        KeyPair rsa384KeyPair = ClientResolverTest.getRSAKey(3072);
        KeyPair rsa512KeyPair = ClientResolverTest.getRSAKey(4096);
        KeyPair ecKeyPair = ClientResolverTest.getECKey();

        return Stream.of(
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.RSA_OAEP_256, rsa256KeyPair.getPrivate()),
                        new VerifiablePresentation().setVerifiableCredential(List.of("myCredential")),
                        new RSASSAVerifier((RSAPublicKey) rsa256KeyPair.getPublic())
                ),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "#myKey", JWEAlgorithm.RSA_OAEP_256, rsa256KeyPair.getPrivate()),
                        new VerifiablePresentation().setVerifiableCredential(List.of("myCredential")),
                        new RSASSAVerifier((RSAPublicKey) rsa256KeyPair.getPublic())
                ),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.RSA_OAEP_384, rsa384KeyPair.getPrivate()),
                        new VerifiablePresentation().setVerifiableCredential(List.of("myCredential")),
                        new RSASSAVerifier((RSAPublicKey) rsa384KeyPair.getPublic())
                ),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.RSA_OAEP_512, rsa512KeyPair.getPrivate()),
                        new VerifiablePresentation().setVerifiableCredential(List.of("myCredential")),
                        new RSASSAVerifier((RSAPublicKey) rsa512KeyPair.getPublic())
                ),
                Arguments.of(
                        new HolderConfiguration(URI.create("did:key:myHolder"), "did:key:myHolder", JWEAlgorithm.ECDH_ES_A256KW, ecKeyPair.getPrivate()),
                        new VerifiablePresentation().setVerifiableCredential(List.of("myCredential")),
                        new ECDSAVerifier((ECPublicKey) ecKeyPair.getPublic())
                )
        );

    }
}
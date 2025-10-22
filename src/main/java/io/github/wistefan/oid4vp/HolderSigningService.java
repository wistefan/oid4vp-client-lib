package io.github.wistefan.oid4vp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.oid4vp.config.HolderConfiguration;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.model.VerifiablePresentation;

import java.security.PrivateKey;
import java.security.interfaces.ECPrivateKey;
import java.util.List;
import java.util.Map;

import static com.nimbusds.jose.JWEAlgorithm.*;

/**
 * Implementation of the SigningService, using the locally provided key to sign the verifiable presentations.
 */
public class HolderSigningService implements SigningService {


    private static final List<JWEAlgorithm> SUPPORTED_RSA_ALGORITHMS = List.of(RSA_OAEP_256, RSA_OAEP_384, RSA_OAEP_512);
    private static final List<JWEAlgorithm> SUPPORTED_ECDH_ES_ALGORITHMS = List.of(ECDH_ES, ECDH_ES_A128KW, ECDH_ES_A192KW, ECDH_ES_A256KW);

    private static final String VP_CLAIM_KEY = "vp";

    private final HolderConfiguration holderConfiguration;
    private final ObjectMapper objectMapper;
    private final JWSSigner signer;

    public HolderSigningService(HolderConfiguration holderConfiguration, ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
        this.holderConfiguration = holderConfiguration;
        this.signer = getSigner(holderConfiguration.signatureAlgorithm(), holderConfiguration.privateKey());
    }

    @Override
    public String signPresentation(VerifiablePresentation verifiablePresentation) {
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer(holderConfiguration.holderId().toString())
                .claim(VP_CLAIM_KEY, objectMapper.convertValue(verifiablePresentation, Map.class))
                .build();
        JWSAlgorithm jwsAlgorithm = CryptoUtils.getAlgorithmForKey(holderConfiguration.privateKey())
                .orElseThrow(() -> new AuthorizationException("The holder signing key is invalid."));

        JWSHeader header = new JWSHeader.Builder(jwsAlgorithm)
                .type(JOSEObjectType.JWT)
                .keyID(holderConfiguration.kid())
                .build();
        SignedJWT signedJWT = new SignedJWT(header, claimsSet);
        try {
            signedJWT.sign(signer);
        } catch (JOSEException e) {
            throw new AuthorizationException("Was not able to sign the presentation.", e);
        }
        return signedJWT.serialize();
    }

    private JWSSigner getSigner(JWEAlgorithm jweAlgorithm, PrivateKey privateKey) {
        if (SUPPORTED_RSA_ALGORITHMS.contains(jweAlgorithm)) {
            try {
                return new RSASSASigner(privateKey);
            } catch (IllegalArgumentException e) {
                throw new AuthorizationException("Was not able to generate the signer from the configured algorithm and key.", e);
            }
        }
        if (SUPPORTED_ECDH_ES_ALGORITHMS.contains(jweAlgorithm) && privateKey instanceof ECPrivateKey ecPrivateKey) {
            try {
                return new ECDSASigner(ecPrivateKey);
            } catch (JOSEException e) {
                throw new AuthorizationException("Was not able to generate the signer from the configured algorithm and key.", e);
            }
        }
        throw new AuthorizationException("Algorithm and key are not supported for signing JWTs.");
    }

}

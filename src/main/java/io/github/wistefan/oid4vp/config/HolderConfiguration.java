package io.github.wistefan.oid4vp.config;

import com.nimbusds.jose.JWEAlgorithm;

import java.net.URI;
import java.security.PrivateKey;

/**
 * Configuration of the holder of credentials to be used for the presentation
 * @param holderId - id of the holder, f.e. did:key:some-key
 * @param kid - kid that corresponds to the key used for signing the presentation, used in the header of the vp
 * @param signatureAlgorithm - algorithm to be used for signing the vp_token, needs to be supported by the provided private key
 * @param privateKey - private key for signing the vp
 */
public record HolderConfiguration(URI holderId, String kid, JWEAlgorithm signatureAlgorithm, PrivateKey privateKey) {
}

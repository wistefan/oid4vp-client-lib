package io.github.wistefan.oid4vp.client;

import com.nimbusds.jwt.SignedJWT;
import reactor.core.publisher.Mono;

import java.security.PublicKey;

/**
 * Interface to resolve clients
 */
public interface ClientResolver {

    /**
     * Check if the given clientId is supported by the resolver
     */
    boolean isSupportedId(String clientId);

    /**
     * Returns the public key of the client. Concrete extraction is implementation specific.
     */
    Mono<PublicKey> getPublicKey(String clientId, SignedJWT jwt);
}

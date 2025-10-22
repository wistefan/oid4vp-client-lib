package io.github.wistefan.oid4vp.client;

import com.nimbusds.jwt.SignedJWT;

import java.security.PublicKey;
import java.util.concurrent.CompletableFuture;

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
    CompletableFuture<PublicKey> getPublicKey(String clientId, SignedJWT jwt);
}

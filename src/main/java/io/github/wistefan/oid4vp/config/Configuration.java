package io.github.wistefan.oid4vp.config;

import java.net.URI;
import java.util.Set;

/**
 * Configuration to be used for the OID4VPClient
 *
 * @param host - host of the application/verifier to get a token for
 * @param path - potential additional sub-path to be used on the host
 * @param clientId - id of the client to get a token for
 * @param scope - scope to be requested
 * @param holder - configuration to be used for the holder of the credentials to be presented
 */
public record Configuration(URI host, String path, String clientId, Set<String> scope, HolderConfiguration holder) {
}

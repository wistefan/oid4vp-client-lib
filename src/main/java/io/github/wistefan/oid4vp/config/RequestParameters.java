package io.github.wistefan.oid4vp.config;

import java.net.URI;
import java.util.Set;
/**
 * Parameters to be used for requesting an access token
 *
 * @param host - host of the application/verifier to get a token for
 * @param path - potential additional sub-path to be used on the host
 * @param clientId - id of the client to get a token for
 * @param scope - scope to be requested
 */
public record RequestParameters(URI host, String path, String clientId, Set<String> scope) {
}

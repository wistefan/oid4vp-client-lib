package io.github.wistefan.oid4vp.model;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

/**
 * Holds the parameters to be provided for the authorizationEndpoint {@link https://datatracker.ietf.org/doc/html/rfc6749#section-3.1}
 */
public record AuthorizationQuery(String state, String nonce, String clientId, Set<String> scope, String responseType) {

    private static final String QUERY_TEMPLATE = "%s=%s";
    private static final String STATE_KEY = "state";
    private static final String NONCE_KEY = "nonce";
    private static final String CLIENT_ID_KEY = "client_id";
    private static final String SCOPE_KEY = "scope";
    private static final String RESPONSE_TYPE_KEY = "response_type";

    /**
     * Return the query as a string in a URI-compatible format
     */
    @Override
    public String toString() {

        return createQuery(STATE_KEY, state) + "&" +
                createQuery(NONCE_KEY, nonce) + "&" +
                createQuery(CLIENT_ID_KEY, clientId) + "&" +
                createQuery(SCOPE_KEY, String.join(" ", scope)) + "&" +
                createQuery(RESPONSE_TYPE_KEY, responseType);
    }

    private String createQuery(String key, String value) {
        String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return String.format(QUERY_TEMPLATE, key, encodedValue);
    }
}

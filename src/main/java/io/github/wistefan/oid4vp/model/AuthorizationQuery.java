package io.github.wistefan.oid4vp.model;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;

import static io.github.wistefan.oid4vp.HttpConstants.*;
import static io.github.wistefan.oid4vp.OIDConstants.*;

/**
 * Holds the parameters to be provided for the authorizationEndpoint {@see https://datatracker.ietf.org/doc/html/rfc6749#section-3.1}
 */
public record AuthorizationQuery(String state, String nonce, String clientId, Set<String> scope, String responseType) {


    /**
     * Return the query as a string in a URI-compatible format
     */
    @Override
    public String toString() {

        return createQuery(STATE_KEY, state) + QUERY_DELIMITER +
                createQuery(NONCE_KEY, nonce) + QUERY_DELIMITER +
                createQuery(CLIENT_ID_KEY, clientId) + QUERY_DELIMITER +
                createQuery(SCOPE_KEY, String.join(" ", scope)) + QUERY_DELIMITER +
                createQuery(RESPONSE_TYPE_KEY, responseType);
    }

    private String createQuery(String key, String value) {
        String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return String.format(QUERY_PART_TEMPLATE, key, encodedValue);
    }
}

package io.github.wistefan.oid4vp.model;

import io.github.wistefan.oid4vp.exception.AuthorizationRequestException;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.*;

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
        StringJoiner stringJoiner = new StringJoiner(QUERY_DELIMITER);

        stringJoiner.add(createQuery(STATE_KEY, state));
        stringJoiner.add(createQuery(NONCE_KEY, nonce));
        stringJoiner.add(createQuery(RESPONSE_TYPE_KEY, responseType));
        Optional.ofNullable(clientId).ifPresent(cId -> stringJoiner.add(createQuery(CLIENT_ID_KEY, cId)));
        Optional.ofNullable(scope).ifPresentOrElse(
                sc -> stringJoiner.add(createQuery(SCOPE_KEY, String.join(" ", sc))),
                () -> {
                    throw new AuthorizationRequestException("Scope required for authorization.");
                });

        return stringJoiner.toString();
    }

    private String createQuery(String key, String value) {
        String encodedValue = URLEncoder.encode(value, StandardCharsets.UTF_8);
        return String.format(QUERY_PART_TEMPLATE, key, encodedValue);
    }
}

package io.github.wistefan.oid4vp.model;

import io.github.wistefan.oid4vp.OIDConstants;
import io.github.wistefan.oid4vp.exception.AuthorizationException;
import io.github.wistefan.oid4vp.exception.AuthorizationRequestException;
import lombok.Builder;
import lombok.Data;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.Set;
import java.util.StringJoiner;

import static io.github.wistefan.oid4vp.HttpConstants.*;
import static io.github.wistefan.oid4vp.OIDConstants.*;

/**
 * Authorization response to be used for presenting the vp
 */
@Builder
@Data
public class AuthorizationFormResponse {


    @Builder.Default
    private String grantType = VP_TOKEN_GRANT_TYPE;
    private String vpToken;
    private Set<String> scopes;
    private String clientId;

    /**
     * Provide the authorization response in a form-encoded format
     */
    public String getAsFormBody() {
        StringJoiner bodyJoiner = new StringJoiner(FORM_DELIMITER);
        Optional.ofNullable(grantType).ifPresentOrElse(gt -> bodyJoiner.add(encode(GRANT_TYPE_KEY) + QUERY_PARAM_DELIMITER + encode(grantType)), () -> {
            throw new AuthorizationException("Authorization response does not contain a grant_type.");
        });
        Optional.ofNullable(vpToken).ifPresentOrElse(vt ->
                bodyJoiner.add(encode(VP_TOKEN_GRANT_TYPE) + QUERY_PARAM_DELIMITER + encode(vpToken)), () -> {
            throw new AuthorizationException("Authorization response does not contain a vp_token.");
        });
        Optional.ofNullable(scopes).ifPresentOrElse(vt -> {
                    StringJoiner scopeJoiner = new StringJoiner(SCOPE_DELIMITER);
                    scopes.forEach(scopeJoiner::add);
                    bodyJoiner.add(encode(SCOPE_KEY) + QUERY_PARAM_DELIMITER + encode(scopeJoiner.toString()));
                },
                () -> {
                    throw new AuthorizationException("Authorization response does not contain a scope.");
                });
        if (clientId != null && !clientId.isEmpty()) {
            bodyJoiner.add(encode(CLIENT_ID_KEY) + QUERY_PARAM_DELIMITER + encode(clientId));
        }
        return bodyJoiner.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

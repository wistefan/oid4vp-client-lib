package io.github.wistefan.oid4vp.model;

import lombok.Builder;
import lombok.Data;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Set;
import java.util.StringJoiner;

/**
 * Authorization response to be used for presenting the vp
 */
@Builder
@Data
public class AuthorizationFormResponse {

    @Builder.Default
    private String grantType = "vp_token";
    private String vpToken;
    private Set<String> scopes;
    private String clientId;

    /**
     * Provide the authorization response in a form-encoded format
     */
    public String getAsFormBody() {
        StringJoiner scopeJoiner = new StringJoiner(" ");
        scopes.forEach(scopeJoiner::add);
        StringJoiner bodyJoiner = new StringJoiner("&");
        bodyJoiner.add(encode("grant_type") + "=" + encode(grantType));
        bodyJoiner.add(encode("vp_token") + "=" + encode(vpToken));
        bodyJoiner.add(encode("scope") + "=" + encode(scopeJoiner.toString()));
        if (clientId != null && !clientId.isEmpty()) {
            bodyJoiner.add(encode("client_id") + "=" + encode(clientId));
        }
        return bodyJoiner.toString();
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }
}

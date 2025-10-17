package io.github.wistefan.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;
import lombok.experimental.Accessors;

/**
 * OAuth 2 conformant token response
 */
@Accessors(chain = true)
@Data
public class TokenResponse {
    @JsonProperty("token_type")
    private String tokenType;
    @JsonProperty("issued_token_type")
    private String issuedTokenType;
    @JsonProperty("expires_in")
    private long expiresIn;
    @JsonProperty("access_token")
    private String accessToken;
    private String scope;
    @JsonProperty("id_token")
    private String idToken;
}

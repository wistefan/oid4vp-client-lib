package io.github.wistefan.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.github.wistefan.dcql.model.DcqlQuery;
import lombok.Data;

/**
 * Object containing the authorization request
 */
@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class AuthorizationRequest {

    @JsonProperty("response_type")
    private String responseType;
    @JsonProperty("response_mode")
    private String responseMode;
    @JsonProperty("client_id")
    private String clientId;
    private String state;
    private String nonce;
    @JsonProperty("dcql_query")
    private DcqlQuery dcqlQuery;
}

package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.nimbusds.jose.jwk.JWK;
import lombok.Data;

import java.util.Map;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class VerificationMethod {

    private String id;
    private String controller;
    private String type;
    @JsonProperty("publicKeyJwk")
    private Map<String, Object> publicKeyJwk;
    @JsonProperty("publicKeyMultibase")
    private String publicKeyMultibase;
}

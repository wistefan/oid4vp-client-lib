package io.github.wistefan.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.net.URI;
import java.util.Set;

/**
 * OpenId Configuration data, as returned from the well-known endpoint
 */
@Data
public class OpenIdConfiguration {

    private String issuer;

    @JsonProperty("authorization_endpoint")
    private URI authorizationEndpoint;

    @JsonProperty("token_endpoint")
    private URI tokenEndpoint;

    @JsonProperty("jwks_uri")
    private URI jwksUri;

    @JsonProperty("scopes_supported")
    private Set<String> scopesSupported;

    @JsonProperty("response_types_supported")
    private Set<String> responseTypesSupported;

    @JsonProperty("response_mode_supported")
    private Set<String> responseModeSupported;

    @JsonProperty("grant_types_supported")
    private Set<String> grantTypesSupported;

    @JsonProperty("subject_types_supported")
    private Set<String> subjectTypesSupported;

    @JsonProperty("id_token_signing_alg_values_supported")
    private Set<String> idTokenSigningAlgValuesSupported;

}

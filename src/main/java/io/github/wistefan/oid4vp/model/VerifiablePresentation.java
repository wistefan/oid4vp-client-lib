package io.github.wistefan.oid4vp.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.net.URI;
import java.util.List;

/**
 * Representation of W3C Verifiable Presentation
 */
@Data
public class VerifiablePresentation {

    @JsonProperty("@context")
    private List<String> atContext = List.of("https://www.w3.org/2018/credentials/v1");

    private List<String> type = List.of("VerifiablePresentation");
    @JsonProperty("verifiableCredential")
    private List<Object> verifiableCredential;
    private URI holder;
}

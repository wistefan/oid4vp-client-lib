package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.annotation.JsonFormat;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Data;

import java.util.List;
import java.util.Set;

@Data
@JsonIgnoreProperties(ignoreUnknown = true)
public class DidDocument {

    private String id;
    @JsonProperty("alsoKnownAs")
    private Set<String> alsoKnownAs;

    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    private Set<String> controller;

    //    @JsonDeserialize(using = VerificationMethodDeserializer.class)
    @JsonProperty("verificationMethod")
    @JsonFormat(with = JsonFormat.Feature.ACCEPT_SINGLE_VALUE_AS_ARRAY)
    private List<VerificationMethod> verificationMethod;

    // we ignore the other parts, since we don't need them for verification
}

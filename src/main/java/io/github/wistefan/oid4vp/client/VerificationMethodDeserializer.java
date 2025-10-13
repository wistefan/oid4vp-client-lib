package io.github.wistefan.oid4vp.client;

import com.fasterxml.jackson.core.JacksonException;
import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.JsonDeserializer;
import com.fasterxml.jackson.databind.JsonNode;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class VerificationMethodDeserializer extends JsonDeserializer<List<VerificationMethod>> {

    @Override
    public List<VerificationMethod> deserialize(JsonParser jsonParser, DeserializationContext deserializationContext) throws IOException, JacksonException {
        JsonNode node = jsonParser.getCodec().readTree(jsonParser);
        List<VerificationMethod> verificationMethods = new ArrayList<>();
        if (node.isObject()) {
            VerificationMethod vm = jsonParser.getCodec().treeToValue(node, VerificationMethod.class);
            verificationMethods.add(vm);
        } else if (node.isArray()) {
            for (JsonNode item : node) {
                VerificationMethod vm = jsonParser.getCodec().treeToValue(item, VerificationMethod.class);
                verificationMethods.add(vm);
            }
        }
        return verificationMethods;
    }
}

package io.github.wistefan.oid4vp.mapping;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.TrustedAuthorityType;

import java.io.IOException;

/**
 * Deserializer to help jackson deserializing the {@link TrustedAuthorityType}
 */
public class TrustedAuthorityTypeDeserializer extends StdDeserializer<TrustedAuthorityType> {

	public TrustedAuthorityTypeDeserializer() {
		super(TrustedAuthorityType.class);
	}

	@Override
	public TrustedAuthorityType deserialize(JsonParser jsonParser, DeserializationContext context)
			throws IOException {
		String value = jsonParser.getText();
		return TrustedAuthorityType.fromValue(value);
	}
}
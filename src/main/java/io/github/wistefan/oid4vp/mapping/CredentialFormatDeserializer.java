package io.github.wistefan.oid4vp.mapping;

import com.fasterxml.jackson.core.JsonParser;
import com.fasterxml.jackson.databind.DeserializationContext;
import com.fasterxml.jackson.databind.deser.std.StdDeserializer;
import io.github.wistefan.dcql.model.CredentialFormat;

import java.io.IOException;

/**
 * Deserializer to help jackson deserializing the {@link CredentialFormat}
 */
public class CredentialFormatDeserializer extends StdDeserializer<CredentialFormat> {

	public CredentialFormatDeserializer() {
		super(CredentialFormat.class);
	}

	@Override
	public CredentialFormat deserialize(JsonParser jsonParser, DeserializationContext context)
			throws IOException {
		String value = jsonParser.getText();
		return CredentialFormat.fromValue(value);
	}
}
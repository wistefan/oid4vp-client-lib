package io.github.wistefan.oid4vp.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.Test;

import java.net.URL;
import java.nio.file.Paths;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

public class FileSystemCredentialsRepositoryTest {

    @Test
    void testLoadCredentials() throws Exception {
        // Arrange
        URL resource = FileSystemCredentialsRepositoryTest.class.getClassLoader().getResource("test-credentials");
        assertNotNull(resource, "Test credentials folder should be found.");
        String credentialsPath = Paths.get(resource.toURI()).toFile().getAbsolutePath();
        CredentialsRepository credentialsRepository = new FileSystemCredentialsRepository(credentialsPath, new ObjectMapper());

        // Act
        List<Credential> credentials = credentialsRepository.getCredentials();

        // Assert
        assertEquals(2, credentials.size(), "Should load exactly two credentials.");

        // Assert SD-JWT credential is loaded and valid
        SdJwtCredential sdJWT = credentials.stream()
                .filter(c -> c.getCredentialFormat() == CredentialFormat.DC_SD_JWT)
                .map(Credential::getRawCredential)
                .filter(SdJwtCredential.class::isInstance)
                .map(SdJwtCredential.class::cast)
                .findFirst()
                .orElseThrow(() -> new AssertionError("SD-JWT credential not found."));

        assertNotNull(sdJWT);

        List<String> sdStrings = null;
        if (sdJWT.getJwtCredential().getPayload().get("_sd") instanceof List sdList) {
            sdStrings = sdList.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        assertNotNull(sdStrings, "_sd claim should exist in SD-JWT.");

        List<String> generated = sdJWT.getDisclosures()
                .stream()
                .map(Disclosure::getSdHash)
                .toList();
        assertTrue(sdStrings.containsAll(generated));

        // Assert JWT credential is loaded
        var jwt = credentials.stream()
                .filter(c -> c.getCredentialFormat() == CredentialFormat.JWT_VC_JSON)
                .findFirst()
                .orElseThrow(() -> new AssertionError("JWT credential not found."));
        assertNotNull(jwt);
    }

}

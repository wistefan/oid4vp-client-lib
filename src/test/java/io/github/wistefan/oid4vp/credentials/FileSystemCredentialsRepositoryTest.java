package io.github.wistefan.oid4vp.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

class FileSystemCredentialsRepositoryTest {

    @Test
    public void test() throws Exception {
        CredentialsRepository credentialsRepository = new FileSystemCredentialsRepository("/home/stefanw/git/wistefan/oid4vp-client-lib/src/test/resources/test-credentials", new ObjectMapper());
        SdJwtCredential sdJWT = credentialsRepository.getCredentials()
                .stream()
                .filter(c -> c.getCredentialFormat() == CredentialFormat.DC_SD_JWT)
                .map(Credential::getRawCredential)
                .filter(SdJwtCredential.class::isInstance)
                .map(SdJwtCredential.class::cast)
                .findFirst()
                .orElseThrow(IllegalArgumentException::new);

        List<String> sdStrings = null;
        if (sdJWT.getJwtCredential().getPayload().get("_sd") instanceof List sdList) {
            sdStrings = sdList.stream()
                    .filter(String.class::isInstance)
                    .map(String.class::cast)
                    .toList();
        }
        List<String> generated = sdJWT.getDisclosures()
                .stream()
                .map(Disclosure::getSdHash)
                .toList();

        assertTrue(sdStrings.containsAll(generated));
    }

}
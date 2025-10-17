package io.github.wistefan.oid4vp.credentials;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.SignedJWT;
import io.github.wistefan.dcql.model.Credential;
import io.github.wistefan.dcql.model.CredentialFormat;
import io.github.wistefan.dcql.model.credential.Disclosure;
import io.github.wistefan.dcql.model.credential.JwtCredential;
import io.github.wistefan.dcql.model.credential.SdJwtCredential;
import io.github.wistefan.oid4vp.exception.CredentialsAccessException;
import lombok.RequiredArgsConstructor;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.text.ParseException;
import java.util.*;

/**
 * Implementation of the {@link  CredentialsRepository}, providing access to Credentials stored inside a folder.
 */
@RequiredArgsConstructor
public class FileSystemCredentialsRepository implements CredentialsRepository {

    /**
     * Key for the sd-hash algorithm used by sd-jwt credentials.
     */
    private static final String SD_ALGORITHM_KEY = "_sd_alg";

    private static final String DISCLOSURE_DELIMITER = "~";

    /**
     * Folder containing the credentials.
     */
    private final String credentialsFolder;
    private final ObjectMapper objectMapper;

    @Override
    public List<Credential> getCredentials() {
        try {
            return Files.walk(Path.of(credentialsFolder)).filter(Files::isRegularFile)
                    .map(this::getFromFile)
                    .toList();

        } catch (IOException e) {
            throw new CredentialsAccessException("Was not able to read the credentials from the file system.", e);
        }
    }

    private Credential getFromFile(Path filePath) {
        try {
            String credentialString = Files.readString(filePath);

            CredentialFileFormat credentialFileFormat = CredentialFileFormat.fromFileName(filePath.toString());
            return switch (credentialFileFormat) {
                case JWT -> readJwtCredential(credentialString);
                case SD_JWT -> readSdJwtCredential(filePath.toString(), credentialString);
                // only JWT and SD_JWT are supported by the current repo implementation
                case LDP -> null;
                case MDOC -> null;
            };
        } catch (IOException e) {
            throw new CredentialsAccessException(String.format("Was not able to read the credential from %s.", filePath), e);
        }
    }

    private Credential readJwtCredential(String jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);

            JwtCredential jwtCredential = new JwtCredential(
                    jwt,
                    signedJWT.getHeader().toJSONObject(),
                    signedJWT.getJWTClaimsSet().toJSONObject(),
                    signedJWT.getSignature().decodeToString());
            return new Credential(CredentialFormat.JWT_VC_JSON, jwtCredential);
        } catch (ParseException e) {
            throw new CredentialsAccessException("Not a valid jwt-credential.", e);
        }
    }

    private Credential readSdJwtCredential(String path, String sdJwt) {
        try {
            String[] sdParts = sdJwt.split(DISCLOSURE_DELIMITER);
            // first part is the plain jwt
            SignedJWT signedJWT = SignedJWT.parse(sdParts[0]);
            Object algorithmClaim = signedJWT.getJWTClaimsSet().getClaim(SD_ALGORITHM_KEY);
            // decode the disclosures
            List<Disclosure> disclosures = Arrays.asList(sdParts)
                    // everything after the first element
                    .subList(1, sdParts.length)
                    .stream()
                    .map(disclosure -> {
                        try {
                            return toDisclosure(disclosure, algorithmClaim);
                        } catch (IOException e) {
                            throw new CredentialsAccessException(String.format("The sd-credential at %s contains an invalid disclosure.", path), e);
                        }
                    })
                    .toList();
            SdJwtCredential sdJwtCredential = new SdJwtCredential(sdJwt,
                    new JwtCredential(sdJwt, signedJWT.getHeader().toJSONObject(), signedJWT.getJWTClaimsSet().toJSONObject(), signedJWT.getSignature().decodeToString()),
                    disclosures);
            return new Credential(CredentialFormat.DC_SD_JWT, sdJwtCredential);
        } catch (ParseException e) {
            throw new CredentialsAccessException("Not a valid jwt-credential.", e);
        }
    }

    // decode the encoded disclosure to a {@link Disclosure} object for dcql-evaluation
    private Disclosure toDisclosure(String encoded, Object sdAlgorithm) throws IOException {
        byte[] sdBytes = Base64.getUrlDecoder().decode(encoded);
        List<?> sdContents = objectMapper.readValue(sdBytes, List.class);
        String salt = null;
        String claim = null;
        if (sdContents.get(0) instanceof String saltElement) {
            salt = saltElement;
        }
        if (sdContents.get(1) instanceof String claimElement) {
            claim = claimElement;
        }
        if (sdAlgorithm instanceof String sdAlgorithmString) {
            return new Disclosure(salt, claim, sdContents.get(2), encoded, sdAlgorithmString);
        }
        throw new IllegalArgumentException("Was not able to create disclosure.");
    }
}

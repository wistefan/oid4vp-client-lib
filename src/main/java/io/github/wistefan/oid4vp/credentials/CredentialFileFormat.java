package io.github.wistefan.oid4vp.credentials;

import lombok.Getter;

import java.util.Arrays;

/**
 * Enum to provide the supported formats of credentials and files containing them
 */
public enum CredentialFileFormat {

    JWT("jwt"),
    SD_JWT("sd_jwt"),
    LDP("ldp"),
    MDOC("mdoc");

    @Getter
    private final String fileExtension;

    CredentialFileFormat(String fileExtension) {
        this.fileExtension = fileExtension;
    }

    /**
     * Extract the format from the file extension.
     */
    public static CredentialFileFormat fromFileName(String fileName) {
        String[] nameParts = fileName.split("\\.");
        String extension = nameParts[nameParts.length - 1];

        return Arrays.stream(values())
                .filter(cfV -> cfV.getFileExtension().equals(extension))
                .findAny()
                .orElseThrow(() -> new IllegalArgumentException(String.format("Unsupported file extension: %s - filename was: %s.", extension, fileName)));
    }
}

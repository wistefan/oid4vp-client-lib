package io.github.wistefan.oid4vp.model;

import io.github.wistefan.oid4vp.exception.ClientResolutionException;
import lombok.Getter;

import java.util.Arrays;

public enum KeyType {
    ED_25519("z6Mk"),
    P_256("zDn"),
    P_384("z82");

    @Getter
    private final String typeIndicator;

    KeyType(String typeIndicator) {
        this.typeIndicator = typeIndicator;
    }

    public static KeyType fromKey(String key) {
        return Arrays.stream(values())
                .filter(v -> key.startsWith(v.getTypeIndicator()))
                .findFirst()
                .orElseThrow(() -> new ClientResolutionException(String.format("Key %s is of unknown type.", key)));
    }
}

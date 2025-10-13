package io.github.wistefan.oid4vp.exception;

/**
 * Exception to thrown in case the client cannot be resolved to a public-key
 */
public class ClientResolutionException extends RuntimeException {
    public ClientResolutionException(String message) {
        super(message);
    }

    public ClientResolutionException(String message, Throwable cause) {
        super(message, cause);
    }
}

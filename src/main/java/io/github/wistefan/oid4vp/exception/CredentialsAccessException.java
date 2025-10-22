package io.github.wistefan.oid4vp.exception;

/**
 * Exception to be thrown in case a required credential cannot be accessed.
 */
public class CredentialsAccessException extends RuntimeException {
    public CredentialsAccessException(String message) {
        super(message);
    }

    public CredentialsAccessException(String message, Throwable cause) {
        super(message, cause);
    }
}

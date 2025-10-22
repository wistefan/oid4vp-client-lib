package io.github.wistefan.oid4vp.exception;

/**
 * Exception to be thrown when something fails during the actual authorization
 */
public class AuthorizationException extends RuntimeException {
    public AuthorizationException(String message) {
        super(message);
    }

    public AuthorizationException(String message, Throwable cause) {
        super(message, cause);
    }
}

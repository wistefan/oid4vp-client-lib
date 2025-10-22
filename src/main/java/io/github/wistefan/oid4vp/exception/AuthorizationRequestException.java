package io.github.wistefan.oid4vp.exception;

/**
 * Exception to  be thrown when retrieval of the authorization-request fails.
 */
public class AuthorizationRequestException extends RuntimeException {
    public AuthorizationRequestException(String message) {
        super(message);
    }

    public AuthorizationRequestException(String message, Throwable cause) {
        super(message, cause);
    }
}

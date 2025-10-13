package io.github.wistefan.oid4vp.exception;

/**
 * Exception to be thrown in case something of issues with a downstream service.
 */
public class BadGatewayException extends RuntimeException {
    public BadGatewayException(String message) {
        super(message);
    }

    public BadGatewayException(String message, Throwable cause) {
        super(message, cause);
    }
}

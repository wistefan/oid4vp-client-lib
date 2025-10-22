package io.github.wistefan.oid4vp.exception;

/**
 * Exception to be thrown in all non-specific exception cases.
 */
public class Oid4VPException extends RuntimeException{
    public Oid4VPException(String message) {
        super(message);
    }

    public Oid4VPException(String message, Throwable cause) {
        super(message, cause);
    }
}

package com.otilm.core.service.acme.eab;

/**
 * The secret registered on the ACME profile does not hold usable HS256 key material — a content type that carries no
 * key, a value that is not base64url, or fewer bytes than HS256 requires. A configuration fault of the profile rather
 * than a wrong credential, so it is reported to the client as an internal error and never as a rejected binding.
 */
public class UnusableEabKeyException extends RuntimeException {

    public UnusableEabKeyException(String reason) {
        super(reason);
    }

    public UnusableEabKeyException(String reason, Throwable cause) {
        super(reason, cause);
    }
}

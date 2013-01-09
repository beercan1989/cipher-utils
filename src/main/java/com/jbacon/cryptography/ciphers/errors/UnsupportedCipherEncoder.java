package com.jbacon.cryptography.ciphers.errors;

public class UnsupportedCipherEncoder extends Exception {

    private static final long serialVersionUID = 4110546215121398783L;

    public UnsupportedCipherEncoder() {
        super();
    }

    public UnsupportedCipherEncoder(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCipherEncoder(final String message) {
        super(message);
    }

    public UnsupportedCipherEncoder(final Throwable cause) {
        super(cause);
    }

}
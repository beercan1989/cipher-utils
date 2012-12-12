package com.jbacon.cryptography.ciphers.errors;

public class UnsupportedCipherType extends Exception {

    private static final long serialVersionUID = -8868283812541841674L;

    public UnsupportedCipherType() {
        super();
    }

    public UnsupportedCipherType(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCipherType(final String message) {
        super(message);
    }

    public UnsupportedCipherType(final Throwable cause) {
        super(cause);
    }

}
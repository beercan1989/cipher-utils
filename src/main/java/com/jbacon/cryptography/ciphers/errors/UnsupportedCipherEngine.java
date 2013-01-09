package com.jbacon.cryptography.ciphers.errors;

public class UnsupportedCipherEngine extends Exception {

    private static final long serialVersionUID = -8868283812541841674L;

    public UnsupportedCipherEngine() {
        super();
    }

    public UnsupportedCipherEngine(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCipherEngine(final String message) {
        super(message);
    }

    public UnsupportedCipherEngine(final Throwable cause) {
        super(cause);
    }

}
package com.jbacon.cryptography.ciphers.errors;

public class UnsupportedCipherEncoderType extends Exception {

    private static final long serialVersionUID = 4110546215121398783L;

    public UnsupportedCipherEncoderType() {
        super();
    }

    public UnsupportedCipherEncoderType(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCipherEncoderType(final String message) {
        super(message);
    }

    public UnsupportedCipherEncoderType(final Throwable cause) {
        super(cause);
    }

}
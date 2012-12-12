package com.jbacon.cryptography.ciphers.errors;

public class UnsupportedCipherDigestType extends Exception {

    private static final long serialVersionUID = 4110546215121398783L;

    public UnsupportedCipherDigestType() {
        super();
    }

    public UnsupportedCipherDigestType(final String message, final Throwable cause) {
        super(message, cause);
    }

    public UnsupportedCipherDigestType(final String message) {
        super(message);
    }

    public UnsupportedCipherDigestType(final Throwable cause) {
        super(cause);
    }

}
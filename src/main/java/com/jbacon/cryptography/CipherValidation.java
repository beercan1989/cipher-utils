package com.jbacon.cryptography;

public final class CipherValidation {
    private CipherValidation() {
    }

    public static void validateInputs(final CipherMode mode, final byte[] key, final byte[] input) {
        if (mode == null) {
            throw new NullPointerException("CipherMode was null.");
        }

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }
    }

    public static void validateInputs(final CipherMode mode, final byte[] input) {
        if (mode == null) {
            throw new NullPointerException("CipherMode was null.");
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }
    }
}

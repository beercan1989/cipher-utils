package com.jbacon.cryptography;

final class CipherValidation {
    private CipherValidation() {
    }

    static final void validateInputs(final CipherMode mode, final byte[] key, final byte[] input) {
        validateInputs(mode, input);

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }
    }

    static void validateInputs(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv,
            final byte[] input) {
        validateInputs(mode, input);

        if (salt == null) {
            throw new NullPointerException("Provided salt was null.");
        }

        if (iv == null) {
            throw new NullPointerException("Provided initialization vector was null.");
        }

        if (password == null) {
            throw new NullPointerException("Provided password was null.");
        }
    }

    static final void validateInputs(final CipherMode mode, final byte[] input) {
        if (mode == null) {
            throw new NullPointerException("CipherMode was null.");
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }
    }
}

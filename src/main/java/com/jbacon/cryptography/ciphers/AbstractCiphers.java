package com.jbacon.cryptography.ciphers;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

abstract class AbstractCiphers {
    enum CipherMode {
        ENCRYPT, //
        DECRYPT; //
    }

    private final BlockCipher cipherEngine;

    protected AbstractCiphers(final BlockCipher cipherEngine) {
        this.cipherEngine = cipherEngine;
    }

    protected static final void validateInputs(final byte[] key, final byte[] input) {
        validateInputs(input);

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }
    }

    protected static void validateInputs(final char[] password, final byte[] salt, final byte[] iv, final byte[] input) {
        validateInputs(input);

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

    protected static final void validateInputs(final byte[] input) {
        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }
    }

    protected final byte[] doCipher(final CipherMode mode, final byte[] input, final CipherParameters cipherParams) throws DataLengthException, IllegalStateException,
            InvalidCipherTextException {

        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine);
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        cipher.reset();
        cipher.init(CipherMode.ENCRYPT.equals(mode), cipherParams);

        final byte[] outputBuffer = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, outputBuffer, 0);
        length += cipher.doFinal(outputBuffer, length);

        final byte[] output = new byte[length];
        System.arraycopy(outputBuffer, 0, output, 0, length);

        return output;
    }
}

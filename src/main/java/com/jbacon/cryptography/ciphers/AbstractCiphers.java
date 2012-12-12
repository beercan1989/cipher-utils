package com.jbacon.cryptography.ciphers;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherType;

abstract class AbstractCiphers {

    protected static enum CipherMode {
        ENCRYPT, //
        DECRYPT; //
    }

    protected static enum CipherEngine {
        AESFast, //
        AESMedium, //
        AESSlow, //
        Twofish; //
    }

    private final CipherEngine cipherEngine;

    protected AbstractCiphers(final CipherEngine cipherEngine) {
        this.cipherEngine = cipherEngine;
    }

    protected final byte[] doCipher(final CipherMode mode, final byte[] input, final CipherParameters cipherParams)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedCipherType {

        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(getCipherEngine(cipherEngine));
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

    private static BlockCipher getCipherEngine(final CipherEngine cipherEngine) throws UnsupportedCipherType {
        switch (cipherEngine) {
        case AESFast:
            return new AESFastEngine();
        case AESMedium:
            return new AESEngine();
        case AESSlow:
            return new AESLightEngine();
        case Twofish:
            return new TwofishEngine();
        default:
            throw new UnsupportedCipherType("Cipher engine not supported.");
        }
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
}

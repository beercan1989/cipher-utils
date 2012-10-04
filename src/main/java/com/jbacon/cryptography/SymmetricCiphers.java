package com.jbacon.cryptography;

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
import org.bouncycastle.crypto.params.KeyParameter;

public enum SymmetricCiphers {
    AES_FAST(new AESFastEngine()), //
    AES(new AESEngine()), //
    AES_SLOW(new AESLightEngine()), //
    TWOFISH(new TwofishEngine());

    private final BlockCipher cipherEngine;

    private SymmetricCiphers(final BlockCipher cipherEngine) {
        this.cipherEngine = cipherEngine;
    }

    public final byte[] encrypt(final byte[] key, final byte[] input) throws DataLengthException,
            IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.ENCRYPT, key, input);
    }

    public final byte[] decrypt(final byte[] key, final byte[] input) throws DataLengthException,
            IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.DECRYPT, key, input);
    }

    private final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        CipherValidation.validateInputs(mode, key, input);
        final KeyParameter keyParameter = new KeyParameter(key);
        return doCipher(mode, input, keyParameter);
    }

    final byte[] doCipher(final CipherMode mode, final byte[] input, final CipherParameters cipherParams)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
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
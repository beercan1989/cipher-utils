package com.jbacon.cryptography.utils;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import com.jbacon.cryptography.CipherMode;
import com.jbacon.cryptography.CipherValidation;

public enum SymmetricCipherUtils {
    AES_FAST(AESFastEngine.class), //
    AES(AESEngine.class), //
    AES_SLOW(AESLightEngine.class), //
    BLOWFISH(BlowfishEngine.class), //
    TWOFISH(TwofishEngine.class);

    private final BlockCipher cipherEngine;

    private SymmetricCipherUtils(final Class<? extends BlockCipher> engineClass) {
        try {
            cipherEngine = engineClass.newInstance();
        } catch (final InstantiationException e) {
            throw new RuntimeException(e);
        } catch (final IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    // TODO - Fix trailing zero bytes on decryption.
    public final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        CipherValidation.validateInputs(mode, key, input);

        final BufferedBlockCipher cipher = createCipher(mode, key);

        final byte[] output = new byte[cipher.getOutputSize(input.length)];
        final int outputLen = cipher.processBytes(input, 0, input.length, output, 0);

        cipher.doFinal(output, outputLen);

        return output;
    }

    private BufferedBlockCipher createCipher(final CipherMode mode, final byte[] key) {
        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine);
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        cipher.init(CipherMode.ENCRYPT.equals(mode), new KeyParameter(key));

        return cipher;
    }
}
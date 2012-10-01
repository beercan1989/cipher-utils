package com.jbacon.cryptography.utils;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

import com.jbacon.cryptography.CipherMode;
import com.jbacon.cryptography.CipherValidation;

public enum PasswordBasedCipherUtils {
    PBE_SHA_AES_CBC(AESFastEngine.class, SHA1Digest.class), //
    PBE_SHA224_AES_CBC(AESFastEngine.class, SHA224Digest.class), //
    PBE_SHA256_AES_CBC(AESFastEngine.class, SHA256Digest.class), //
    PBE_SHA384_AES_CBC(AESFastEngine.class, SHA384Digest.class), //
    PBE_SHA512_AES_CBC(AESFastEngine.class, SHA512Digest.class), //
    PBE_TIGER_AES_CBC(AESFastEngine.class, TigerDigest.class), //
    PBE_WHIRLPOOL_AES_CBC(AESFastEngine.class, WhirlpoolDigest.class);

    // Digest => Symmetric Cipher => CBC
    private final BlockCipher cipherEngine;
    private final Digest digestEngine;

    private PasswordBasedCipherUtils(final Class<? extends BlockCipher> engineClass,
            final Class<? extends Digest> digestClass) {
        try {
            cipherEngine = engineClass.newInstance();
            digestEngine = digestClass.newInstance();
        } catch (final InstantiationException e) {
            throw new RuntimeException(e);
        } catch (final IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

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
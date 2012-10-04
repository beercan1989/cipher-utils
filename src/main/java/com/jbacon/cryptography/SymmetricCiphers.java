package com.jbacon.cryptography;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.params.KeyParameter;

public final class SymmetricCiphers extends AbstractCiphers {
    public static final SymmetricCiphers AES_FAST = new SymmetricCiphers(new AESFastEngine());
    public static final SymmetricCiphers AES = new SymmetricCiphers(new AESEngine());
    public static final SymmetricCiphers AES_SLOW = new SymmetricCiphers(new AESLightEngine());
    public static final SymmetricCiphers TWOFISH = new SymmetricCiphers(new TwofishEngine());

    private SymmetricCiphers(final BlockCipher cipherEngine) {
        super(cipherEngine);
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
        validateInputs(mode, key, input);
        final KeyParameter keyParameter = new KeyParameter(key);
        return doCipher(mode, input, keyParameter);
    }

}
package com.jbacon.cryptography.ciphers;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.params.KeyParameter;

/**
 * This class provides easy access to certain Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * Please Note:<br />
 * The AES ciphers can only handle key size's of 128/192/256 bits.<br />
 * The Twofish cipher cannot have a key size smaller than 64 bits or larger than 256 bits.
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class SymmetricCiphers extends AbstractCiphers {
    public static final SymmetricCiphers AES_FAST = new SymmetricCiphers(new AESFastEngine());
    public static final SymmetricCiphers AES = new SymmetricCiphers(new AESEngine());
    public static final SymmetricCiphers AES_SLOW = new SymmetricCiphers(new AESLightEngine());
    public static final SymmetricCiphers TWOFISH = new SymmetricCiphers(new TwofishEngine());

    private SymmetricCiphers(final BlockCipher cipherEngine) {
        super(cipherEngine);
    }

    /**
     * Encrypts the input using the chosen cipher and key.
     * 
     * @param key the cipher key to use.
     * @param input the data to encrypt.
     * 
     * @return the encrypted data.
     * 
     * @exception InvalidCipherTextException if padding is expected and not found.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    public final byte[] encrypt(final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.ENCRYPT, key, input);
    }

    /**
     * Decrypts the input using the chosen cipher and key.
     * 
     * @param key the cipher key to use.
     * @param input the data to decrypt.
     * 
     * @return the decrypted data.
     * 
     * @exception InvalidCipherTextException if padding is expected and not found.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     */
    public final byte[] decrypt(final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.DECRYPT, key, input);
    }

    private final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        validateInputs(key, input);
        final KeyParameter keyParameter = new KeyParameter(key);
        return doCipher(mode, input, keyParameter);
    }

}
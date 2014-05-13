package co.uk.baconi.cryptography.ciphers.symmetric;

import static co.uk.baconi.cryptography.ciphers.CipherMode.DECRYPT;
import static co.uk.baconi.cryptography.ciphers.CipherMode.ENCRYPT;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import co.uk.baconi.annotations.VisibleForTesting;
import co.uk.baconi.cryptography.ciphers.AbstractCiphers;
import co.uk.baconi.cryptography.ciphers.CipherMode;
import co.uk.baconi.cryptography.utils.SecureRandomUtil;

/**
 * This class provides easy access to certain Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * Please Note:<br />
 * The AES ciphers can only handle key size's of 128/192/256 bits.<br />
 * The TWOFISH cipher cannot have a key size smaller than 64 bits or larger than 256 bits.
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class SymmetricCiphers extends AbstractCiphers {
    
    private static final Log LOG = LogFactory.getLog(SymmetricCiphers.class);
    
    public static final SymmetricCiphers AES_FAST = new SymmetricCiphers(SymmetricCipherEngines.AES_FAST);
    public static final SymmetricCiphers AES = new SymmetricCiphers(SymmetricCipherEngines.AES_MEDIUM);
    public static final SymmetricCiphers AES_SLOW = new SymmetricCiphers(SymmetricCipherEngines.AES_SLOW);
    public static final SymmetricCiphers TWOFISH = new SymmetricCiphers(SymmetricCipherEngines.TWOFISH);
    
    private SymmetricCiphers(final SymmetricCipherEngines symmetricCipherEngine) {
        super(symmetricCipherEngine);
    }
    
    /**
     * Encrypts the input using the chosen cipher and key.
     * 
     * @param key
     *            the cipher key to use.
     * @param input
     *            the data to encrypt.
     * 
     * @return the encrypted data.
     * 
     * @exception InvalidCipherTextException
     *                if padding is expected and not found.
     * @exception DataLengthException
     *                if there isn't enough space in out.
     * @exception IllegalStateException
     *                if the cipher isn't initialised.
     * @throws IOException
     * @exception UnsupportedCipherEngine
     *                if the cipher engine is not currently supported.
     */
    public final byte[] encrypt(final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        return doCipher(ENCRYPT, key, input);
    }
    
    /**
     * Decrypts the input using the chosen cipher and key.
     * 
     * @param key
     *            the cipher key to use.
     * @param input
     *            the data to decrypt.
     * 
     * @return the decrypted data.
     * 
     * @exception InvalidCipherTextException
     *                if padding is expected and not found.
     * @exception DataLengthException
     *                if there isn't enough space in out.
     * @exception IllegalStateException
     *                if the cipher isn't initialised.
     * @throws IOException
     * @exception UnsupportedCipherEngine
     *                if the cipher engine is not currently supported.
     */
    public final byte[] decrypt(final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        return doCipher(DECRYPT, key, input);
    }
    
    private final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException,
            IOException {
        validateInputs(key, input);
        final KeyParameter keyParameter = new KeyParameter(key);
        return doCipher(mode, input, keyParameter);
    }
    
    @Override
    public String toString() {
        return toString(this);
    }
    
    public static String toString(final SymmetricCiphers symmetricCipher) {
        final String string = symmetricCipher.getCipherEngine().name();
        
        LOG.debug("toString:" + string);
        
        return string;
    }
    
    public static SymmetricCiphers fromString(final String string) {
        LOG.debug("fromString:" + string);
        
        if (string == null) {
            throw new IllegalArgumentException();
        }
        
        final SymmetricCipherEngines symmetricCipherEngine = SymmetricCipherEngines.valueOf(string);
        
        if (symmetricCipherEngine == null) {
            throw new IllegalArgumentException();
        }
        
        return new SymmetricCiphers(symmetricCipherEngine);
    }
    
    /**
     * @param strength
     *            key strength in bits
     * @return the generated key of length <code>strength</code>
     */
    public byte[] generateKey(final int strength) {
        final CipherKeyGenerator keyGenerator = symmetricCipherEngine.getKeyGenerator();
        keyGenerator.init(new KeyGenerationParameters(SecureRandomUtil.getSecureRandom(), strength));
        return keyGenerator.generateKey();
    }
    
    @VisibleForTesting
    public CipherKeyGenerator getKeyGenerator() {
        return symmetricCipherEngine.getKeyGenerator();
    }
}
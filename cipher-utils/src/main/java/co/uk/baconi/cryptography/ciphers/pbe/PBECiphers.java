package co.uk.baconi.cryptography.ciphers.pbe;

import static co.uk.baconi.cryptography.ciphers.CipherMode.DECRYPT;
import static co.uk.baconi.cryptography.ciphers.CipherMode.ENCRYPT;
import static co.uk.baconi.cryptography.ciphers.pbe.Digests.MD5;
import static co.uk.baconi.cryptography.ciphers.pbe.Digests.SHA1;
import static co.uk.baconi.cryptography.ciphers.pbe.Digests.SHA256;
import static co.uk.baconi.cryptography.ciphers.pbe.Digests.SHA512;
import static co.uk.baconi.cryptography.ciphers.pbe.Digests.WHIRLPOOL;
import static co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCipherEngines.AES_FAST;
import static co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCipherEngines.DES;
import static co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCipherEngines.TWOFISH;

import java.io.IOException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import co.uk.baconi.cryptography.CipherKeySize;
import co.uk.baconi.cryptography.ciphers.AbstractCiphers;
import co.uk.baconi.cryptography.ciphers.CipherMode;
import co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCipherEngines;

/**
 * This class provides easy access to a PBE solution built up on the BouncyCastle lightweight api.
 * 
 * The Ciphers used in the PBE's have been set to 256bit keys, as this is the highest supported key size using the BouncyCastle's lightweight api.
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class PBECiphers extends AbstractCiphers {
    
    private static final Log LOG = LogFactory.getLog(PBECiphers.class);
    
    @Deprecated
    public static final PBECiphers PBE_MD5_DES_CBC = new PBECiphers(DES, MD5);
    @Deprecated
    public static final PBECiphers PBE_MD5_AES_CBC = new PBECiphers(AES_FAST, MD5);
    @Deprecated
    public static final PBECiphers PBE_SHA1_AES_CBC = new PBECiphers(AES_FAST, SHA1);
    public static final PBECiphers PBE_SHA256_AES_CBC = new PBECiphers(AES_FAST, SHA256);
    public static final PBECiphers PBE_SHA512_AES_CBC = new PBECiphers(AES_FAST, SHA512);
    public static final PBECiphers PBE_WHIRLPOOL_AES_CBC = new PBECiphers(AES_FAST, WHIRLPOOL);
    
    @Deprecated
    public static final PBECiphers PBE_MD5_TWOFISH_CBC = new PBECiphers(TWOFISH, MD5);
    @Deprecated
    public static final PBECiphers PBE_SHA1_TWOFISH_CBC = new PBECiphers(TWOFISH, SHA1);
    public static final PBECiphers PBE_SHA256_TWOFISH_CBC = new PBECiphers(TWOFISH, SHA256);
    public static final PBECiphers PBE_SHA512_TWOFISH_CBC = new PBECiphers(TWOFISH, SHA512);
    public static final PBECiphers PBE_WHIRLPOOL_TWOFISH_CBC = new PBECiphers(TWOFISH, WHIRLPOOL);
    
    private static final int ITERATION_COUNT = 50;
    private static final String CBC = ";CBC";
    private static final String PBE = "PBE;";
    private static final String TO_STRING_DIVIDER = ";";
    
    private final Digests digest;
    
    private PBECiphers(final SymmetricCipherEngines symmetricCipherEngine, final Digests digest) {
        super(symmetricCipherEngine);
        this.digest = digest;
    }
    
    /**
     * Encrypts the input using PBE.
     * 
     * @param password
     *            the users password used to generate the cipher key.
     * @param salt
     *            an array of random bytes that will be combined with the password to generate the cipher key.
     * @param iv
     *            the initialisation vector, a random array of bytes. Similar to salt in its function.
     * @param input
     *            The data to encrypt.
     * 
     * @return The encrypted data.
     * 
     * @exception InvalidCipherTextException
     *                if padding is expected and not found.
     * @exception DataLengthException
     *                if there isn't enough space in out.
     * @exception IllegalStateException
     *                if the cipher isn't initialised.
     * @throws IOException
     * @exception UnsupportedCipherDigestType
     *                if the Digests type is not currently supported.
     * @exception UnsupportedCipherEngine
     *                if the Cipher type is not currently supported.
     */
    public final byte[] encrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, IOException {
        return doCipher(ENCRYPT, password, salt, iv, input);
    }
    
    /**
     * Decrypts the input using PBE.
     * 
     * @param password
     *            the users password used to generate the cipher key.
     * @param salt
     *            an array of random bytes that will be combined with the password to generate the cipher key.
     * @param iv
     *            the initialisation vector, a random array of bytes. Similar to salt in its function.
     * @param input
     *            the data to decrypt using the password, salt and iv.
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
     * @exception UnsupportedCipherDigestType
     *                if the Digests type is not currently supported.
     * @exception UnsupportedCipherEngine
     *                if the Cipher type is not currently supported.
     */
    public final byte[] decrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws DataLengthException, IllegalStateException,
            InvalidCipherTextException, IOException {
        return doCipher(DECRYPT, password, salt, iv, input);
    }
    
    private byte[] doCipher(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws DataLengthException,
            IllegalStateException, InvalidCipherTextException, IOException {
        validateInputs(password, salt, iv, input);
        
        final KeyParameter keyParam = new KeyParameter(generateEncryptionKey(password, salt, ITERATION_COUNT, CipherKeySize.KS_256.getKeySize()));
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);
        
        final byte[] output = doCipher(mode, input, cipherParams);
        
        return output;
    }
    
    private byte[] generateEncryptionKey(final char[] password, final byte[] salt, final int iterationCount, final int keySize) {
        final CipherParameters param = makePBEParameters(password, salt, iterationCount, keySize, CipherKeySize.KS_128.getKeySize());
        
        if (param instanceof ParametersWithIV) {
            return ((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey();
        } else {
            return ((KeyParameter) param).getKey();
        }
    }
    
    private CipherParameters makePBEParameters(final char[] password, final byte[] salt, final int iterationCount, final int keySize, final int ivSize) {
        final PBEParametersGenerator generator = new PKCS12ParametersGenerator(digest.getInstance());
        final byte[] key = PBEParametersGenerator.PKCS12PasswordToBytes(password);
        CipherParameters param;
        
        generator.init(key, salt, iterationCount);
        
        if (ivSize != 0) {
            param = generator.generateDerivedParameters(keySize, ivSize);
        } else {
            param = generator.generateDerivedParameters(keySize);
        }
        
        for (int i = 0; i != key.length; i++) {
            key[i] = 0;
        }
        
        return param;
    }
    
    @Override
    public String toString() {
        return toString(this);
    }
    
    public static String toString(final PBECiphers pbeCipher) {
        final StringBuilder toString = new StringBuilder();
        toString.append(PBE);
        toString.append(pbeCipher.digest.name());
        toString.append(TO_STRING_DIVIDER);
        toString.append(pbeCipher.getCipherEngine().name());
        toString.append(CBC);
        final String string = toString.toString();
        
        LOG.debug("toString:" + string);
        
        return string;
    }
    
    public static PBECiphers fromString(final String string) {
        LOG.debug("fromString:" + string);
        
        if (string == null) {
            throw new IllegalArgumentException();
        }
        
        final String[] split = string.split(TO_STRING_DIVIDER);
        
        if (split == null || split.length != 4) {
            throw new IllegalArgumentException();
        }
        
        final SymmetricCipherEngines symmetricCipherEngine = SymmetricCipherEngines.valueOf(split[2]);
        final Digests digest = Digests.valueOf(split[1]);
        
        if (symmetricCipherEngine == null || digest == null) {
            throw new IllegalArgumentException();
        }
        
        return new PBECiphers(symmetricCipherEngine, digest);
    }
}
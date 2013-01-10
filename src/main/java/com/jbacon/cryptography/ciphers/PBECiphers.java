package com.jbacon.cryptography.ciphers;

import static com.jbacon.cryptography.ciphers.AbstractCiphers.CipherEngine.AESFast;
import static com.jbacon.cryptography.ciphers.AbstractCiphers.CipherEngine.Twofish;
import static com.jbacon.cryptography.ciphers.AbstractCiphers.CipherMode.DECRYPT;
import static com.jbacon.cryptography.ciphers.AbstractCiphers.CipherMode.ENCRYPT;
import static com.jbacon.cryptography.ciphers.PBECiphers.Digest.MD5;
import static com.jbacon.cryptography.ciphers.PBECiphers.Digest.SHA1;
import static com.jbacon.cryptography.ciphers.PBECiphers.Digest.SHA256;
import static com.jbacon.cryptography.ciphers.PBECiphers.Digest.SHA512;
import static com.jbacon.cryptography.ciphers.PBECiphers.Digest.Whirlpool;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.jbacon.cryptography.CipherKeySize;
import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherDigestType;
import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEngine;

/**
 * This class provides easy access to a PBE solution built up on the BouncyCastle lightweight api.
 * 
 * The Ciphers used in the PBE's have been set to 256bit keys, as this is the highest supported key size using the
 * BouncyCastle's lightweight api.
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class PBECiphers extends AbstractCiphers {

    @Deprecated
    public static final PBECiphers PBE_MD5_AES_CBC = new PBECiphers(AESFast, MD5);
    @Deprecated
    public static final PBECiphers PBE_SHA1_AES_CBC = new PBECiphers(AESFast, SHA1);
    public static final PBECiphers PBE_SHA256_AES_CBC = new PBECiphers(AESFast, SHA256);
    public static final PBECiphers PBE_SHA512_AES_CBC = new PBECiphers(AESFast, SHA512);
    public static final PBECiphers PBE_WHIRLPOOL_AES_CBC = new PBECiphers(AESFast, Whirlpool);

    @Deprecated
    public static final PBECiphers PBE_MD5_TWOFISH_CBC = new PBECiphers(Twofish, MD5);
    @Deprecated
    public static final PBECiphers PBE_SHA1_TWOFISH_CBC = new PBECiphers(Twofish, SHA1);
    public static final PBECiphers PBE_SHA256_TWOFISH_CBC = new PBECiphers(Twofish, SHA256);
    public static final PBECiphers PBE_SHA512_TWOFISH_CBC = new PBECiphers(Twofish, SHA512);
    public static final PBECiphers PBE_WHIRLPOOL_TWOFISH_CBC = new PBECiphers(Twofish, Whirlpool);

    private static final int ITERATION_COUNT = 50;

    protected static enum Digest {
        @Deprecated
        MD5, //
        @Deprecated
        SHA1, //
        SHA256, //
        SHA512, //
        Whirlpool;

        protected ExtendedDigest getInstance() throws UnsupportedCipherDigestType {
            switch (this) {
            case MD5:
                return new MD5Digest();
            case SHA1:
                return new SHA1Digest();
            case SHA256:
                return new SHA256Digest();
            case SHA512:
                return new SHA512Digest();
            case Whirlpool:
                return new WhirlpoolDigest();
            default:
                throw new UnsupportedCipherDigestType("Digest not supported.");
            }
        }
    }

    private final Digest digest;

    private PBECiphers(final CipherEngine cipherEngine, final Digest digest) {
        super(cipherEngine);
        this.digest = digest;
    }

    /**
     * Encrypts the input using PBE.
     * 
     * @param password the users password used to generate the cipher key.
     * @param salt an array of random bytes that will be combined with the password to generate the cipher key.
     * @param iv the initialisation vector, a random array of bytes. Similar to salt in its function.
     * @param input The data to encrypt.
     * 
     * @return The encrypted data.
     * 
     * @exception InvalidCipherTextException if padding is expected and not found.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @exception UnsupportedCipherDigestType if the Digest type is not currently supported.
     * @exception UnsupportedCipherEngine if the Cipher type is not currently supported.
     */
    public final byte[] encrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedCipherEngine,
            UnsupportedCipherDigestType {
        return doCipher(ENCRYPT, password, salt, iv, input);
    }

    /**
     * Decrypts the input using PBE.
     * 
     * @param password the users password used to generate the cipher key.
     * @param salt an array of random bytes that will be combined with the password to generate the cipher key.
     * @param iv the initialisation vector, a random array of bytes. Similar to salt in its function.
     * @param input the data to decrypt using the password, salt and iv.
     * 
     * @return the decrypted data.
     * 
     * @exception InvalidCipherTextException if padding is expected and not found.
     * @exception DataLengthException if there isn't enough space in out.
     * @exception IllegalStateException if the cipher isn't initialised.
     * @exception UnsupportedCipherDigestType if the Digest type is not currently supported.
     * @exception UnsupportedCipherEngine if the Cipher type is not currently supported.
     */
    public final byte[] decrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedCipherEngine,
            UnsupportedCipherDigestType {
        return doCipher(DECRYPT, password, salt, iv, input);
    }

    private byte[] doCipher(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv,
            final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException,
            UnsupportedCipherEngine, UnsupportedCipherDigestType {
        validateInputs(password, salt, iv, input);

        final KeyParameter keyParam = new KeyParameter(generateEncryptionKey(password, salt, ITERATION_COUNT,
                CipherKeySize.KS_256.getKeySize()));
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = doCipher(mode, input, cipherParams);

        return output;
    }

    private byte[] generateEncryptionKey(final char[] password, final byte[] salt, final int iterationCount,
            final int keySize) throws UnsupportedCipherDigestType {
        final CipherParameters param = makePBEParameters(password, salt, iterationCount, keySize,
                CipherKeySize.KS_128.getKeySize());

        if (param instanceof ParametersWithIV) {
            return ((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey();
        } else {
            return ((KeyParameter) param).getKey();
        }
    }

    private CipherParameters makePBEParameters(final char[] password, final byte[] salt, final int iterationCount,
            final int keySize, final int ivSize) throws UnsupportedCipherDigestType {
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
}
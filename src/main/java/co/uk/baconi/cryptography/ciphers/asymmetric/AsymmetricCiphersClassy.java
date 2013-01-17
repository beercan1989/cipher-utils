package co.uk.baconi.cryptography.ciphers.asymmetric;

import static co.uk.baconi.cryptography.ciphers.CipherMode.DECRYPT;
import static co.uk.baconi.cryptography.ciphers.CipherMode.ENCRYPT;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEnginesClassy.EL_GAMAL;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEnginesClassy.NACCACHE_STERN;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEnginesClassy.RSA;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricEncodings.PKCS1;

import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import co.uk.baconi.cryptography.ciphers.CipherMode;

/**
 * @deprecated Use {@link AsymmetricCiphers} instead.
 */
@Deprecated
final class AsymmetricCiphersClassy {

    public static final AsymmetricCiphersClassy ELGAMAL_PKCS1 = new AsymmetricCiphersClassy(EL_GAMAL, PKCS1);
    public static final AsymmetricCiphersClassy NACCACHE_STERN_PKCS1 = new AsymmetricCiphersClassy(NACCACHE_STERN,
            PKCS1);
    public static final AsymmetricCiphersClassy RSA_PKCS1 = new AsymmetricCiphersClassy(RSA, PKCS1);

    private static final String TO_STRING_DIVIDER = ";";
    private static final Log LOG = LogFactory.getLog(AsymmetricCiphersClassy.class);

    private final AsymmetricEncodings asymmetricEncoder;
    private final AsymmetricCipherEnginesClassy<?, ?> asymmetricCipherEngine;

    private AsymmetricCiphersClassy(final AsymmetricCipherEnginesClassy<?, ?> asymmetricCipherEngine,
            final AsymmetricEncodings asymmetricEncoder) {
        this.asymmetricEncoder = asymmetricEncoder;
        this.asymmetricCipherEngine = asymmetricCipherEngine;
    }

    /**
     * Encrypts the message using the provided key.
     * 
     * @param keyData the encryption key.
     * @param messageData the message to encrypt.
     * @return the encrypted message.
     * @throws InvalidCipherTextException - when the data encrypts improperly.
     * @throws DataLengthException - when the input data is too large for the cipher.
     * @throws IOException - on an error decoding the key
     * @throws UnsupportedCipherEngine - when an unsupported cipher engine has been used.
     * @throws UnsupportedCipherEncoder - when an unsupported cipher encoder has been used.
     */
    public byte[] encrypt(final byte[] keyData, final byte[] messageData) throws InvalidCipherTextException,
            IOException {
        return doCipher(ENCRYPT, keyData, messageData);
    }

    /**
     * Decrypts the message using the provided key.
     * 
     * @param keyData the decryption key.
     * @param messageData the message to decrypt.
     * @return the decrypted message.
     * @throws InvalidCipherTextException - when the data decrypts improperly.
     * @throws DataLengthException - when the input data is too large for the cipher.
     * @throws IOException - on an error decoding the key
     * @throws UnsupportedCipherEngine - when an unsupported cipher engine has been used.
     * @throws UnsupportedCipherEncoder - when an unsupported cipher encoder has been used.
     */
    public byte[] decrypt(final byte[] keyData, final byte[] messageData) throws InvalidCipherTextException,
            IOException {
        return doCipher(DECRYPT, keyData, messageData);
    }

    private byte[] doCipher(final CipherMode mode, final byte[] keyData, final byte[] messageData)
            throws InvalidCipherTextException, IOException {
        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Mode [");
            sb.append(mode);
            sb.append("], Key [");
            sb.append(Arrays.toString(keyData));
            sb.append("], Message [");
            sb.append(messageData);
            sb.append("], Cipher Engine [");
            sb.append(asymmetricCipherEngine);
            sb.append("], Encoder Type[");
            sb.append(asymmetricEncoder);
            sb.append("]");
            LOG.debug(sb.toString());
        }

        if (keyData == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }

        if (messageData == null) {
            throw new NullPointerException("Provided message data was null.");
        }

        final AsymmetricBlockCipher cipherAndEncoding = getCipherAndEncoding();
        final AsymmetricKeyParameter key = getKey(mode, keyData);

        cipherAndEncoding.init(mode.isEncrypt(), key);

        return cipherAndEncoding.processBlock(messageData, 0, messageData.length);
    }

    private AsymmetricKeyParameter getKey(final CipherMode mode, final byte[] keyData) throws IOException {
        return ENCRYPT.equals(mode) ? PrivateKeyFactory.createKey(keyData) : PublicKeyFactory.createKey(keyData);
    }

    private AsymmetricBlockCipher getCipherAndEncoding() {
        return asymmetricEncoder.getInstance(asymmetricCipherEngine.getInstance());
    }

    @Override
    public String toString() {
        return toString(this);
    }

    public AsymmetricCipherKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
        return asymmetricCipherEngine.getKeyGenerator(params);
    }

    public AsymmetricCipherKeyPairGenerator getKeyGenerator() {
        return asymmetricCipherEngine.getKeyGenerator();
    }

    public static String toString(final AsymmetricCiphersClassy asymmetricCipher) {
        final StringBuilder toString = new StringBuilder();
        toString.append(asymmetricCipher.asymmetricCipherEngine.name());
        toString.append(TO_STRING_DIVIDER);
        toString.append(asymmetricCipher.asymmetricEncoder.name());
        final String string = toString.toString();

        LOG.debug("toString:" + string);

        return string;
    }

    public static AsymmetricCiphersClassy fromString(final String string) {
        LOG.debug("fromString:" + string);

        if (string == null) {
            throw new IllegalArgumentException();
        }

        final String[] split = string.split(TO_STRING_DIVIDER);

        if (split == null || split.length != 2) {
            throw new IllegalArgumentException();
        }

        final AsymmetricCipherEnginesClassy<?, ?> asymmetricCipherEngine = valueOf(split[0]);
        final AsymmetricEncodings asymmetricEncoder = AsymmetricEncodings.valueOf(split[1]);

        if (asymmetricCipherEngine == null || asymmetricEncoder == null) {
            throw new IllegalArgumentException();
        }

        return new AsymmetricCiphersClassy(asymmetricCipherEngine, asymmetricEncoder);
    }

    private static AsymmetricCipherEnginesClassy<?, ?> valueOf(final String string) {
        if (EL_GAMAL.name().equalsIgnoreCase(string)) {
            return EL_GAMAL;
        }

        if (NACCACHE_STERN.name().equalsIgnoreCase(string)) {
            return NACCACHE_STERN;
        }

        return RSA;
    }
}
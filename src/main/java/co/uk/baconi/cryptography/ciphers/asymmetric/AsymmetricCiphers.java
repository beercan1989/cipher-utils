package co.uk.baconi.cryptography.ciphers.asymmetric;

import static co.uk.baconi.cryptography.ciphers.CipherMode.DECRYPT;
import static co.uk.baconi.cryptography.ciphers.CipherMode.ENCRYPT;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEngines.EL_GAMAL;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEngines.NACCACHE_STERN;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCipherEngines.RSA;
import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricEncodings.PKCS1;
import static co.uk.baconi.cryptography.utils.SecureRandomUtil.getSecureRandom;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

import co.uk.baconi.cryptography.ciphers.CipherMode;
import co.uk.baconi.cryptography.utils.SecureRandomUtil;

/**
 * This class provides easy access to certain Asymmetric Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class AsymmetricCiphers<T extends AlgorithmParameterSpec> {

    public static final AsymmetricCiphers<ElGamalParameterSpec> ELGAMAL_PKCS1 = new AsymmetricCiphers<ElGamalParameterSpec>(
            EL_GAMAL, PKCS1);
    public static final AsymmetricCiphers<AlgorithmParameterSpec> NACCACHE_STERN_PKCS1 = new AsymmetricCiphers<AlgorithmParameterSpec>(
            NACCACHE_STERN, PKCS1);
    public static final AsymmetricCiphers<RSAKeyGenParameterSpec> RSA_PKCS1 = new AsymmetricCiphers<RSAKeyGenParameterSpec>(
            RSA, PKCS1);

    private static final String TO_STRING_DIVIDER = ";";
    private static final Log LOG = LogFactory.getLog(AsymmetricCiphers.class);

    private final AsymmetricEncodings asymmetricEncoder;
    private final AsymmetricCipherEngines asymmetricCipherEngine;

    private AsymmetricCiphers(final AsymmetricCipherEngines asymmetricCipherEngine,
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

    /**
     * Create a KeyPair using the default parameters for the KeyPairGenerator.
     * 
     * @return a new generated KeyPair.
     */
    public KeyPair generateKeyPair() {
        return asymmetricCipherEngine.getKeyPairGenerator().generateKeyPair();
    }

    /**
     * Create a KeyPair using custom KeyPairGenerator parameters. If in doubt use {@link #generateKeyPair()}.
     * 
     * @param keyGenParams the custom parameters for the KeyPairGenerator.
     * @return a new generated KeyPair.
     * @throws InvalidAlgorithmParameterException if the parameters are not supported by the cipher engine.
     */
    public KeyPair generateKeyPair(final T keyGenParams) throws InvalidAlgorithmParameterException {
        final KeyPairGenerator generator = asymmetricCipherEngine.getKeyPairGenerator();
        generator.initialize(keyGenParams, SecureRandomUtil.getSecureRandom());
        return generator.generateKeyPair();
    }

    /**
     * Create the custom parameters for the RSA KeyPairGenerator.
     * 
     * @param keySize the size of they key to generate.
     * @param publicExponent
     * @return the generated parameters for the RSA KeyPairGenerator.
     */
    public RSAKeyGenParameterSpec generateRsaKeyGenerationParams(final int keySize, final BigInteger publicExponent) {
        return new RSAKeyGenParameterSpec(keySize, publicExponent);
    }

    /**
     * Create the custom parameters for the ElGamal KeyPairGenerator.
     * 
     * @param keySize the size of they key to generate.
     * @param certainty the certainty level that the primes generated are true primes.
     * @return the generated parameters for the ElGamal KeyPairGenerator.
     */
    public ElGamalParameterSpec generateElGamalKeyGenerationParams(final int keySize, final int certainty) {
        final ElGamalParametersGenerator paramGenerator = new ElGamalParametersGenerator();
        paramGenerator.init(keySize, certainty, getSecureRandom());
        final ElGamalParameters generateParameters = paramGenerator.generateParameters();
        return new ElGamalParameterSpec(generateParameters.getP(), generateParameters.getG());
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

    public static <T extends AlgorithmParameterSpec> String toString(final AsymmetricCiphers<T> asymmetricCipher) {
        final StringBuilder toString = new StringBuilder();
        toString.append(asymmetricCipher.asymmetricCipherEngine.name());
        toString.append(TO_STRING_DIVIDER);
        toString.append(asymmetricCipher.asymmetricEncoder.name());
        final String string = toString.toString();

        LOG.debug("toString:" + string);

        return string;
    }

    public static <T extends AlgorithmParameterSpec> AsymmetricCiphers<AlgorithmParameterSpec> fromString(
            final String string) {
        LOG.debug("fromString:" + string);

        if (string == null) {
            throw new IllegalArgumentException();
        }

        final String[] split = string.split(TO_STRING_DIVIDER);

        if (split == null || split.length != 2) {
            throw new IllegalArgumentException();
        }

        final AsymmetricCipherEngines asymmetricCipherEngine = AsymmetricCipherEngines.valueOf(split[0]);
        final AsymmetricEncodings asymmetricEncoder = AsymmetricEncodings.valueOf(split[1]);

        if (asymmetricCipherEngine == null || asymmetricEncoder == null) {
            throw new IllegalArgumentException();
        }

        return new AsymmetricCiphers<AlgorithmParameterSpec>(asymmetricCipherEngine, asymmetricEncoder);
    }
}
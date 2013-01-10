package com.jbacon.cryptography.ciphers;

import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.AsymmetricCipherEngines.ElGamalEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.AsymmetricCipherEngines.NaccacheSternEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.AsymmetricCipherEngines.RSAEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.AsymmetricEncoders.PKCS1;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherMode.DECRYPT;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherMode.ENCRYPT;

import java.io.IOException;
import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;
import org.bouncycastle.crypto.util.PublicKeyFactory;

import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEncoder;
import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEngine;

/**
 * This class provides easy access to certain Asymmetric Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class AsymmetricCiphers {

    public static final AsymmetricCiphers ELGAMAL_PKCS1 = new AsymmetricCiphers(ElGamalEngine, PKCS1);
    public static final AsymmetricCiphers NACCACHE_STERN_PKCS1 = new AsymmetricCiphers(NaccacheSternEngine, PKCS1);
    public static final AsymmetricCiphers RSA_PKCS1 = new AsymmetricCiphers(RSAEngine, PKCS1);

    private static final Log LOG = LogFactory.getLog(AsymmetricCiphers.class);

    protected static enum CipherMode {
        ENCRYPT, //
        DECRYPT; //
    }

    protected static enum AsymmetricCipherEngines {
        ElGamalEngine, //
        NaccacheSternEngine, //
        RSAEngine; //

        public AsymmetricBlockCipher getInstance() throws UnsupportedCipherEngine {
            switch (this) {
            case ElGamalEngine:
                return new ElGamalEngine();
            case NaccacheSternEngine:
                return new NaccacheSternEngine();
            case RSAEngine:
                return new RSAEngine();
            default:
                throw new UnsupportedCipherEngine("Asymmetric cipher engine not supported.");
            }
        }
    }

    protected static enum AsymmetricEncoders {
        OAEP, //
        PKCS1, //
        ISO9796d1; //

        public AsymmetricBlockCipher getInstance(final AsymmetricBlockCipher cipherEngine)
                throws UnsupportedCipherEncoder {
            switch (this) {
            case PKCS1:
                return new PKCS1Encoding(cipherEngine);
            default:
                throw new UnsupportedCipherEncoder("Asymmetric encoder not supported.");
            }
        }
    }

    private final AsymmetricEncoders asymmetricEncoder;
    private final AsymmetricCipherEngines asymmetricCipherEngine;

    private AsymmetricCiphers(final AsymmetricCipherEngines asymmetricCipherEngine,
            final AsymmetricEncoders asymmetricEncoder) {
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
            IOException, UnsupportedCipherEngine, UnsupportedCipherEncoder {
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
            IOException, UnsupportedCipherEngine, UnsupportedCipherEncoder {
        return doCipher(DECRYPT, keyData, messageData);
    }

    private byte[] doCipher(final CipherMode mode, final byte[] keyData, final byte[] messageData)
            throws InvalidCipherTextException, IOException, UnsupportedCipherEncoder, UnsupportedCipherEngine {
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

        cipherAndEncoding.init(ENCRYPT.equals(mode), key);

        return cipherAndEncoding.processBlock(messageData, 0, messageData.length);
    }

    private AsymmetricKeyParameter getKey(final CipherMode mode, final byte[] keyData) throws IOException {
        return ENCRYPT.equals(mode) ? PrivateKeyFactory.createKey(keyData) : PublicKeyFactory.createKey(keyData);
    }

    private AsymmetricBlockCipher getCipherAndEncoding() throws UnsupportedCipherEncoder, UnsupportedCipherEngine {
        return asymmetricEncoder.getInstance(asymmetricCipherEngine.getInstance());
    }
}
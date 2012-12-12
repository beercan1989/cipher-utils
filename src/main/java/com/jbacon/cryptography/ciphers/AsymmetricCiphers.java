package com.jbacon.cryptography.ciphers;

import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherEngine.ElGamalEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherEngine.NaccacheSternEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherEngine.RSAEngine;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherMode.DECRYPT;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.CipherMode.ENCRYPT;
import static com.jbacon.cryptography.ciphers.AsymmetricCiphers.EncoderType.PKCS1;

import java.io.IOException;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEncoderType;
import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherType;

/**
 * This class provides easy access to certain Asymmetric Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * Please Note:<br />
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class AsymmetricCiphers {

    public static final AsymmetricCiphers ELGAMAL_PKCS1 = new AsymmetricCiphers(ElGamalEngine, PKCS1);
    public static final AsymmetricCiphers NACCACHE_STERN_PKCS1 = new AsymmetricCiphers(NaccacheSternEngine, PKCS1);
    public static final AsymmetricCiphers RSA_PKCS1 = new AsymmetricCiphers(RSAEngine, PKCS1);

    protected static enum CipherMode {
        ENCRYPT, //
        DECRYPT; //
    }

    protected static enum CipherEngine {
        ElGamalEngine, //
        NaccacheSternEngine, //
        RSAEngine; //
    }

    protected static enum EncoderType {
        OAEP, //
        PKCS1, //
        ISO9796d1; //
    }

    private final EncoderType encoderType;
    private final CipherEngine cipherEngine;

    private AsymmetricCiphers(final CipherEngine cipherEngine, final EncoderType encoderType) {
        this.encoderType = encoderType;
        this.cipherEngine = cipherEngine;
    }

    public byte[] encrypt(final byte[] keyData, final byte[] messageData) throws InvalidCipherTextException,
            IOException, UnsupportedCipherType, UnsupportedCipherEncoderType {
        return doCipher(ENCRYPT, keyData, messageData);
    }

    public byte[] decrypt(final byte[] keyData, final byte[] messageData) throws InvalidCipherTextException,
            IOException, UnsupportedCipherType, UnsupportedCipherEncoderType {
        return doCipher(DECRYPT, keyData, messageData);
    }

    private byte[] doCipher(final CipherMode mode, final byte[] keyData, final byte[] messageData)
            throws InvalidCipherTextException, IOException, UnsupportedCipherEncoderType, UnsupportedCipherType {
        final AsymmetricBlockCipher cipherAndEncoding = getCipherAndEncoding();
        final AsymmetricKeyParameter key = PrivateKeyFactory.createKey(keyData);

        cipherAndEncoding.init(ENCRYPT.equals(mode), key);

        return cipherAndEncoding.processBlock(messageData, 0, messageData.length);
    }

    private AsymmetricBlockCipher getCipherAndEncoding() throws UnsupportedCipherEncoderType, UnsupportedCipherType {
        return getEncoder(encoderType, getCipher(cipherEngine));
    }

    private static AsymmetricBlockCipher getCipher(final CipherEngine cipherEngine) throws UnsupportedCipherType {
        switch (cipherEngine) {
        case ElGamalEngine:
            return new ElGamalEngine();
        case NaccacheSternEngine:
            return new NaccacheSternEngine();
        case RSAEngine:
            return new RSAEngine();
        default:
            throw new UnsupportedCipherType("Cipher engine not supported.");
        }
    }

    private static AsymmetricBlockCipher getEncoder(final EncoderType encoderType,
            final AsymmetricBlockCipher cipherEngine) throws UnsupportedCipherEncoderType {
        switch (encoderType) {
        case PKCS1:
            return new PKCS1Encoding(cipherEngine);
        default:
            throw new UnsupportedCipherEncoderType("Encoder type not supported.");
        }
    }
}
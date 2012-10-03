package com.jbacon.cryptography.utils;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jcajce.provider.symmetric.util.BCPBEKey;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE;
import org.bouncycastle.jcajce.provider.symmetric.util.PBE.Util;

import com.jbacon.cryptography.CipherMode;

public enum PasswordBasedCipherUtils {
    PBE_SHA_AES_CBC(AESFastEngine.class, SHA1Digest.class), //
    PBE_SHA256_AES_CBC(AESFastEngine.class, SHA256Digest.class), //
    PBE_SHA_TWOFISH_CBC(TwofishEngine.class, SHA1Digest.class); //

    private final BlockCipher cipherEngine;
    private final ExtendedDigest digestEngine;

    private final int iterationCount = 50;
    private final int keyLength;
    private final String secretKeyFactoryName;

    private PasswordBasedCipherUtils(final Class<? extends BlockCipher> engineClass, final Class<? extends ExtendedDigest> digestClass) {
        try {
            cipherEngine = engineClass.newInstance();
            digestEngine = digestClass.newInstance();

            this.keyLength = 0;

            if (cipherEngine instanceof AESFastEngine) {
                if (digestEngine instanceof SHA1Digest) {
                    secretKeyFactoryName = "PBEWithSHA1And256BitAES-CBC-BC";
                } else if (digestEngine instanceof SHA256Digest) {
                    secretKeyFactoryName = "PBEWithSHA256And256BitAES-CBC-BC";
                } else {
                    throw new RuntimeException("Unsupported Cipher or Digest");
                }
            } else if (cipherEngine instanceof TwofishEngine) {
                if (digestEngine instanceof SHA1Digest) {
                    secretKeyFactoryName = "PBEwithSHAandTwofish-CBC";
                } else {
                    throw new RuntimeException("Unsupported Cipher or Digest");
                }
            } else {
                throw new RuntimeException("Unsupported Cipher or Digest");
            }

        } catch (final InstantiationException e) {
            throw new RuntimeException(e);
        } catch (final IllegalAccessException e) {
            throw new RuntimeException(e);
        }
    }

    public final byte[] doCipher(final CipherMode mode, final char[] password, final byte[] salt, final byte[] input) throws DataLengthException, IllegalStateException,
            InvalidCipherTextException {
        // Salt
        // Password
        // Iteration Count

        // TODO
        return null;
    }

    private BufferedBlockCipher createCipher(final CipherMode mode, final char[] password) {
        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine);
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        // TODO
        // cipher.init(CipherMode.ENCRYPT.equals(mode), new KeyParameter(key));

        return cipher;
    }

    /**
     * Test Method.
     * 
     * @param mode
     * @param password
     * @param salt
     * @param iv
     *            Initialisation Vector - To help scramble the cipher text.
     * @param input
     *            The String to encrypt.
     * @return The encrypted String.
     * 
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeySpecException
     * @throws InvalidCipherTextException
     * @throws IllegalStateException
     * @throws DataLengthException
     */
    public final byte[] test(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws NoSuchAlgorithmException,
            InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException {

        final PBEKeySpec pbeKeySpecification = new PBEKeySpec(password, salt, iterationCount, 256);
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");

        final SecretKeySpec secretKeySpecification = new SecretKeySpec(secretKeyFactory.generateSecret(pbeKeySpecification).getEncoded(), "AES");
        final byte[] generatedEncryptionKey = secretKeySpecification.getEncoded();
        final KeyParameter keyParam = new KeyParameter(generatedEncryptionKey);
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = SymmetricCipherUtils.AES_FAST.doCipher(CipherMode.ENCRYPT, input, cipherParams);

        return output;
    }

    public final byte[] test2(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws NoSuchAlgorithmException,
            InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException {

        final PBEKeySpec pbeKeySpecification = new PBEKeySpec(password, salt, iterationCount, 256);
        final SecretKey generateSecret = engineGenerateSecret(pbeKeySpecification);
        final SecretKeySpec secretKeySpecification = new SecretKeySpec(generateSecret.getEncoded(), "AES");
        final byte[] generatedEncryptionKey = secretKeySpecification.getEncoded();
        final KeyParameter keyParam = new KeyParameter(generatedEncryptionKey);
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = SymmetricCipherUtils.AES_FAST.doCipher(CipherMode.ENCRYPT, input, cipherParams);

        return output;
    }

    /*
     * Keep this as it works. Make more flexible in the SecretKey Generation.
     */
    private SecretKey engineGenerateSecret(final PBEKeySpec pbeSpec) throws InvalidKeySpecException {
        if (pbeSpec.getSalt() == null) {
            return new BCPBEKey("", null, PBE.PKCS12, PBE.SHA256, pbeSpec.getKeyLength(), 128, pbeSpec, null);
        }
        final CipherParameters param = Util.makePBEParameters(pbeSpec, PBE.PKCS12, PBE.SHA256, pbeSpec.getKeyLength(), 128);
        return new BCPBEKey("", null, PBE.PKCS12, PBE.SHA256, pbeSpec.getKeyLength(), 128, pbeSpec, param);
    }
}
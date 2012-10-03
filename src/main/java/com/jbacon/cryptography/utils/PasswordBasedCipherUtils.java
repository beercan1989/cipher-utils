package com.jbacon.cryptography.utils;

import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA224Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA384Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.TigerDigest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.jbacon.cryptography.CipherMode;

public enum PasswordBasedCipherUtils {
    PBE_SHA_AES_CBC(AESFastEngine.class, SHA1Digest.class, true), //
    PBE_SHA224_AES_CBC(AESFastEngine.class, SHA224Digest.class, true), //
    PBE_SHA256_AES_CBC(AESFastEngine.class, SHA256Digest.class, true), //
    PBE_SHA384_AES_CBC(AESFastEngine.class, SHA384Digest.class, true), //
    PBE_SHA512_AES_CBC(AESFastEngine.class, SHA512Digest.class, true), //
    PBE_TIGER_AES_CBC(AESFastEngine.class, TigerDigest.class, true), //
    PBE_WHIRLPOOL_AES_CBC(AESFastEngine.class, WhirlpoolDigest.class, true), //

    PBE_SHA_BLOWFISH_CBC(BlowfishEngine.class, SHA1Digest.class, true), //
    PBE_SHA224_BLOWFISH_CBC(BlowfishEngine.class, SHA224Digest.class, true), //
    PBE_SHA256_BLOWFISH_CBC(BlowfishEngine.class, SHA256Digest.class, true), //
    PBE_SHA384_BLOWFISH_CBC(BlowfishEngine.class, SHA384Digest.class, true), //
    PBE_SHA512_BLOWFISH_CBC(BlowfishEngine.class, SHA512Digest.class, true), //
    PBE_TIGER_BLOWFISH_CBC(BlowfishEngine.class, TigerDigest.class, true), //
    PBE_WHIRLPOOL_BLOWFISH_CBC(BlowfishEngine.class, WhirlpoolDigest.class, true),

    PBE_SHA_TWOFISH_ECB(TwofishEngine.class, SHA1Digest.class, false), //
    PBE_SHA224_TWOFISH_ECB(TwofishEngine.class, SHA224Digest.class, false), //
    PBE_SHA256_TWOFISH_ECB(TwofishEngine.class, SHA256Digest.class, false), //
    PBE_SHA384_TWOFISH_ECB(TwofishEngine.class, SHA384Digest.class, false), //
    PBE_SHA512_TWOFISH_ECB(TwofishEngine.class, SHA512Digest.class, false), //
    PBE_TIGER_TWOFISH_ECB(TwofishEngine.class, TigerDigest.class, false), //
    PBE_WHIRLPOOL_TWOFISH_ECB(TwofishEngine.class, WhirlpoolDigest.class, false);

    // Digest => Symmetric Cipher => CBC / ECB
    private final BlockCipher cipherEngine;
    private final Digest digestEngine;
    private final boolean isCBC;

    private PasswordBasedCipherUtils(final Class<? extends BlockCipher> engineClass, final Class<? extends Digest> digestClass, final boolean isCBC) {
        try {
            cipherEngine = engineClass.newInstance();
            digestEngine = digestClass.newInstance();
            this.isCBC = isCBC;
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
    public byte[] test(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws NoSuchAlgorithmException,
            InvalidKeySpecException, DataLengthException, IllegalStateException, InvalidCipherTextException {

        final PBEKeySpec pbeKeySpecification = new PBEKeySpec(password, salt, 50, 256);
        final SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance("PBEWithSHA256And256BitAES-CBC-BC");
        final SecretKeySpec secretKeySpecification = new SecretKeySpec(secretKeyFactory.generateSecret(pbeKeySpecification).getEncoded(), "AES");
        final byte[] generatedEncryptionKey = secretKeySpecification.getEncoded();
        final KeyParameter keyParam = new KeyParameter(generatedEncryptionKey);
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = SymmetricCipherUtils.AES_FAST.doCipher(CipherMode.ENCRYPT, input, cipherParams);

        return output;
    }
}
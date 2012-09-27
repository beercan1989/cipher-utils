package com.jbacon.utils;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
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
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.BlowfishEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;

public final class CipherUtils {
    private CipherUtils() {
    }

    public static final String bytesToBase64Encoded(final byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static final byte[] base64EncodedToBytes(final String base64Encoded) {
        return Base64.decodeBase64(base64Encoded);
    }

    public static String byteToString(final byte[] byteToString) throws UnsupportedEncodingException {
        return new String(byteToString, "UTF-8");
    }

    public static byte[] stringToByte(final String stringToByte) throws UnsupportedEncodingException {
        return stringToByte.getBytes("UTF-8");
    }

    public enum CipherMode {
        ENCRYPT(), //
        DECRYPT(); //
    }

    public enum SymmetricCipher {
        // TODO - Implement more Ciphers.
        AES_FAST(AESFastEngine.class), //
        AES(AESEngine.class), //
        AES_SLOW(AESLightEngine.class), //
        BLOWFISH(BlowfishEngine.class), //
        TWOFISH(TwofishEngine.class);

        private final BlockCipher cipherEngine;

        private SymmetricCipher(final Class<? extends BlockCipher> engineClass) {
            try {
                this.cipherEngine = engineClass.newInstance();
            } catch (final InstantiationException e) {
                throw new RuntimeException(e);
            } catch (final IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }

        // TODO - Fix trailing zero bytes on decryption.
        public final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
            validateInputs(mode, key, input);

            final BufferedBlockCipher cipher = createCipher(mode, key);

            final byte[] output = new byte[cipher.getOutputSize(input.length)];
            final int outputLen = cipher.processBytes(input, 0, input.length, output, 0);

            cipher.doFinal(output, outputLen);

            return output;
        }

        private BufferedBlockCipher createCipher(final CipherMode mode, final byte[] key) {
            final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine);
            final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

            cipher.init(CipherMode.ENCRYPT.equals(mode), new KeyParameter(key));

            return cipher;
        }
    }

    public enum PasswordBasedCipher {
        PBE_SHA_AES_CBC(AESFastEngine.class, SHA1Digest.class), //
        PBE_SHA224_AES_CBC(AESFastEngine.class, SHA224Digest.class), //
        PBE_SHA256_AES_CBC(AESFastEngine.class, SHA256Digest.class), //
        PBE_SHA384_AES_CBC(AESFastEngine.class, SHA384Digest.class), //
        PBE_SHA512_AES_CBC(AESFastEngine.class, SHA512Digest.class), //
        PBE_TIGER_AES_CBC(AESFastEngine.class, TigerDigest.class), //
        PBE_WHIRLPOOL_AES_CBC(AESFastEngine.class, WhirlpoolDigest.class);

        // Digest => Symmetric Cipher => CBC
        private final BlockCipher cipherEngine;
        private final Digest digestEngine;

        private PasswordBasedCipher(final Class<? extends BlockCipher> engineClass, final Class<? extends Digest> digestClass) {
            try {
                this.cipherEngine = engineClass.newInstance();
                this.digestEngine = digestClass.newInstance();
            } catch (final InstantiationException e) {
                throw new RuntimeException(e);
            } catch (final IllegalAccessException e) {
                throw new RuntimeException(e);
            }
        }

        public final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
            validateInputs(mode, key, input);

            final BufferedBlockCipher cipher = createCipher(mode, key);

            final byte[] output = new byte[cipher.getOutputSize(input.length)];
            final int outputLen = cipher.processBytes(input, 0, input.length, output, 0);

            cipher.doFinal(output, outputLen);

            return output;
        }

        private BufferedBlockCipher createCipher(final CipherMode mode, final byte[] key) {
            final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine);
            final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

            cipher.init(CipherMode.ENCRYPT.equals(mode), new KeyParameter(key));

            return cipher;
        }
    }

    private static void validateInputs(final CipherMode mode, final byte[] key, final byte[] input) {
        if (mode == null) {
            throw new NullPointerException("CipherMode was null.");
        }

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }
    }
}

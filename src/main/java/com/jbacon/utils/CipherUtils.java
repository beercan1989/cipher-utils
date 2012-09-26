package com.jbacon.utils;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESFastEngine;
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
        AES();

        // TODO - Fix trailing zero bytes on decryption.
        public final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input)
                throws DataLengthException, IllegalStateException, InvalidCipherTextException {
            validateInputs(mode, key, input);

            final BufferedBlockCipher cipher = getCipher(mode, key);

            final byte[] output = new byte[cipher.getOutputSize(input.length)];
            final int outputLen = cipher.processBytes(input, 0, input.length, output, 0);

            cipher.doFinal(output, outputLen);

            return output;
        }

        private BufferedBlockCipher getCipher(final CipherMode mode, final byte[] key) {
            switch (this) {
            case AES:
                return createCipher(new AESFastEngine(), mode, key);
            default:
                return null;
            }
        }

        private BufferedBlockCipher createCipher(final BlockCipher engine, final CipherMode mode, final byte[] key) {
            final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(engine);
            final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

            cipher.init(CipherMode.ENCRYPT.equals(mode), new KeyParameter(key));

            return cipher;
        }
    }

    public enum PasswordBasedCipher {
        PBEWithMD5AndDES, //
        PBEWithMD5AndRC2, //
        PBEWithSHA1AndDES, //
        PBEWithSHA1AndRC2, //
        PBEWithSHAAnd2_KeyTripleDES_CBC, //
        PBEWithSHAAnd3_KeyTripleDES_CBC, //
        PBEWithSHAAnd128BitRC2_CBC, //
        PBEWithSHAAnd40BitRC2_CBC, //
        PBEWithSHAAnd128BitRC4, //
        PBEWithSHAAnd40BitRC4, //
        PBEWithSHAAndTwofish_CBC, //
        PBEWithSHAAndIDEA_CBC;

        public final byte[] doCipher(final CipherMode mode, final byte[] key, final byte[] input)
                throws DataLengthException, IllegalStateException, InvalidCipherTextException {
            validateInputs(mode, key, input);

            final BufferedBlockCipher cipher = getCipher(mode, key);

            final byte[] output = new byte[cipher.getOutputSize(input.length)];
            final int outputLen = cipher.processBytes(input, 0, input.length, output, 0);

            cipher.doFinal(output, outputLen);

            return output;
        }

        private BufferedBlockCipher getCipher(final CipherMode mode, final byte[] key) {
            switch (this) {
            case PBEWithMD5AndDES:
                return createPBEWithMD5AndDESCiper();
            case PBEWithMD5AndRC2:
                return null;
            case PBEWithSHA1AndDES:
                return null;
            case PBEWithSHA1AndRC2:
                return null;
            case PBEWithSHAAnd2_KeyTripleDES_CBC:
                return null;
            case PBEWithSHAAnd3_KeyTripleDES_CBC:
                return null;
            case PBEWithSHAAnd128BitRC2_CBC:
                return null;
            case PBEWithSHAAnd40BitRC2_CBC:
                return null;
            case PBEWithSHAAnd128BitRC4:
                return null;
            case PBEWithSHAAnd40BitRC4:
                return null;
            case PBEWithSHAAndTwofish_CBC:
                return null;
            case PBEWithSHAAndIDEA_CBC:
                return null;
            default:
                return null;
            }
        }

        private BufferedBlockCipher createPBEWithMD5AndDESCiper() {
            return null;
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

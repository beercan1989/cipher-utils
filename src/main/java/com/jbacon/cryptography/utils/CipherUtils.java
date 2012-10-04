package com.jbacon.cryptography.utils;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

import org.apache.commons.codec.binary.Base64;

public final class CipherUtils {
    private static final String SHA1PRNG = "SHA1PRNG";
    private static final String UTF8 = "UTF-8";

    private CipherUtils() {
    }

    /**
     * Converts a UTF-8 byte array into a Base64 Encoded String.
     * 
     * @param bytes
     *            The UTF-8 Encoded byte array.
     * @return A String containing the Base64 Encoded values of the UTF-8 byte array or <strong>null</strong> if the <strong>bytes</strong> param is <strong>null</strong>.
     */
    public static final String bytesToBase64EncodedString(final byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    /**
     * Converts a Base64 Encoded String into a UTF-8 Encoded byte array.
     * 
     * @param base64String
     *            The Base64 Encoded String.
     * @return A UTF-8 byte array of the Decoded Base64 String or <strong>null</strong> if the <strong>base64String</strong> param is <strong>null</strong>.
     */
    public static final byte[] base64EncodedStringToBytes(final String base64String) {
        return Base64.decodeBase64(base64String);
    }

    /**
     * Converts a UTF-8 byte array into a String.
     * 
     * @param bytes
     *            The UTF-8 byte array to covnert into a String.
     * @return A String made from the UTF-8 byte array or <strong>null</strong> if the <strong>bytes</strong> param is <strong>null</strong>.
     */
    public static String byteToString(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }
        try {
            return new String(bytes, UTF8);
        } catch (final UnsupportedEncodingException e) {
        }

        return null;
    }

    /**
     * Converts a String to a UTF-8 encoded byte array.
     * 
     * @param string
     *            The String to convert into a UTF-8 byte array.
     * @return A UTF-8 encoded byte array or <strong>null</strong> if the <strong>string</strong> param is <strong>null</strong>.
     */
    public static byte[] stringToByte(final String string) {
        try {
            return string.getBytes(UTF8);
        } catch (final UnsupportedEncodingException e) {
        } catch (final NullPointerException e) {
        }

        return null;
    }

    /**
     * Generates a byte array using a secure <em>random</em> generator.
     * 
     * @param numberOfBytes
     * @return
     * @throws NoSuchAlgorithmException
     */
    public static byte[] generateSalt(final int numberOfBytes) throws NoSuchAlgorithmException {
        final byte[] salt = new byte[numberOfBytes];
        final SecureRandom saltGen = SecureRandom.getInstance(SHA1PRNG);
        saltGen.nextBytes(salt);
        return salt;
    }
}

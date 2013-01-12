package co.uk.baconi.cryptography.utils;

import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.util.encoders.Base64;

public final class CipherUtils {
    private static final String EMPTY = "";
    private static final String PROVIDER = "SUN";
    private static final String SECURE_RANDOM_ALGORITHM = "SHA1PRNG";
    private static final String UTF8 = "UTF-8";

    private static final Log LOG = LogFactory.getLog(CipherUtils.class);

    private CipherUtils() {
    }

    /**
     * Converts a UTF-8 byte array into a Base64 Encoded String.
     * 
     * @param bytes The UTF-8 Encoded byte array.
     * @return A String containing the Base64 Encoded values of the UTF-8 byte array or <strong>null</strong> if the
     *         <strong>bytes</strong> param is <strong>null</strong>.
     */
    public static final String bytesToBase64Encoded(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        return byteToString(Base64.encode(bytes));
        // return Base64.encodeBase64String(bytes); // commons-lang
    }

    /**
     * Converts a Base64 Encoded String into a UTF-8 Encoded byte array.
     * 
     * @param base64String The Base64 Encoded String.
     * @return A UTF-8 byte array of the Decoded Base64 String or <strong>null</strong> if the
     *         <strong>base64String</strong> param is <strong>null</strong>.
     */
    public static final byte[] base64EncodedStringToBytes(final String base64String) {
        if (base64String == null) {
            return null;
        }

        return Base64.decode(stringToByte(base64String));
        // return Base64.decodeBase64(base64String); // commons-lang
    }

    /**
     * Converts a UTF-8 byte array into a String.
     * 
     * @param bytes The UTF-8 byte array to covnert into a String.
     * @return A String made from the UTF-8 byte array or <strong>null</strong> if the <strong>bytes</strong> param is
     *         <strong>null</strong>.
     */
    public static final String byteToString(final byte[] bytes) {
        if (bytes == null) {
            return null;
        }

        try {
            return new String(bytes, UTF8);
        } catch (final UnsupportedEncodingException e) {
            LOG.error(EMPTY, e);
        }

        return null;
    }

    /**
     * Converts a String to a UTF-8 encoded byte array.
     * 
     * @param string The String to convert into a UTF-8 byte array.
     * @return A UTF-8 encoded byte array or <strong>null</strong> if the <strong>string</strong> param is
     *         <strong>null</strong>.
     */
    public static final byte[] stringToByte(final String string) {
        if (string == null) {
            return null;
        }

        try {
            return string.getBytes(UTF8);
        } catch (final UnsupportedEncodingException e) {
            LOG.error(EMPTY, e);
        }

        return null;
    }

    /**
     * Generates a byte array using a secure <em>random</em> generator.
     * 
     * @param numberOfBytes
     * @return
     * @throws NoSuchAlgorithmException This is thrown if their isn't a provider for the 'SHA1PRNG'
     */
    public static final byte[] generateBytes(final int numberOfBytes) {
        final byte[] salt = new byte[numberOfBytes];
        final SecureRandom saltGen = getSecureRandom();
        saltGen.nextBytes(salt);
        return salt;
    }

    private static final SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM, PROVIDER);
        } catch (final NoSuchProviderException e) {
            LOG.error(EMPTY, e);
            try {
                return SecureRandom.getInstance(SECURE_RANDOM_ALGORITHM);
            } catch (final NoSuchAlgorithmException e1) {
                LOG.error(EMPTY, e1);
            }
        } catch (final NoSuchAlgorithmException e) {
            LOG.error(EMPTY, e);
        }
        return new SecureRandom();
    }
}

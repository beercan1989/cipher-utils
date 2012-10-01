package com.jbacon.cryptography.utils;

import java.io.UnsupportedEncodingException;

import org.apache.commons.codec.binary.Base64;

public final class GenericCipherUtils {
    private static final String UTF8 = "UTF-8";

    private GenericCipherUtils() {
    }

    public static final String bytesToBase64Encoded(final byte[] bytes) {
        return Base64.encodeBase64String(bytes);
    }

    public static final byte[] base64EncodedToBytes(final String base64Encoded) {
        return Base64.decodeBase64(base64Encoded);
    }

    public static String byteToString(final byte[] byteToString) throws UnsupportedEncodingException {
        return new String(byteToString, UTF8);
    }

    public static byte[] stringToByte(final String stringToByte) throws UnsupportedEncodingException {
        return stringToByte.getBytes(UTF8);
    }
}

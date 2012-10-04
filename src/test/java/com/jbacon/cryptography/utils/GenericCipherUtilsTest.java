package com.jbacon.cryptography.utils;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

public class GenericCipherUtilsTest {

    private static final String STRING_HELLOWORLD_AS_BASE64 = "SGVsbG8gV29ybGQ=";
    private static final byte[] BYTEARRAY_HELLOWORLD = new byte[] { 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100 };

    @Test
    public void shouldConvertByteArrayToBase64EncodedString() {
        final String base64Encoded = CipherUtils.bytesToBase64EncodedString(BYTEARRAY_HELLOWORLD);
        assertThat(base64Encoded, is(equalTo(STRING_HELLOWORLD_AS_BASE64)));
    }

    @Test
    public void shouldConvertBase64EncodedStringToByteArray() {
        final byte[] bytes = CipherUtils.base64EncodedStringToBytes(STRING_HELLOWORLD_AS_BASE64);
        assertThat(bytes, is(equalTo(BYTEARRAY_HELLOWORLD)));
    }

    @Test
    public void shouldHandleNullBase64StringToByteArray() {
        final byte[] bytes = CipherUtils.base64EncodedStringToBytes(null);
        assertThat(bytes, is(equalTo(null)));
    }

    @Test
    public void shouldHandleNullByteArrayToBase64String() {
        final String base64Encoded = CipherUtils.bytesToBase64EncodedString(null);
        assertThat(base64Encoded, is(equalTo(null)));
    }
}

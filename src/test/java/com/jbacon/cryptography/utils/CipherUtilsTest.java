package com.jbacon.cryptography.utils;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.junit.Assert.assertThat;

import org.junit.Test;

import com.jbacon.cryptography.utils.GenericCipherUtils;

public class CipherUtilsTest {

    private static final String STRING_HELLOWORLD_AS_BASE64 = "SGVsbG8gV29ybGQ=";
    private static final byte[] BYTEARRAY_HELLOWORLD = new byte[] { 72, 101, 108, 108, 111, 32, 87, 111, 114, 108, 100 };

    @Test
    public void shouldConvertByteArrayToBase64EncodedString() {
        final String base64Encoded = GenericCipherUtils.bytesToBase64Encoded(BYTEARRAY_HELLOWORLD);
        assertThat(base64Encoded, is(equalTo(STRING_HELLOWORLD_AS_BASE64)));
    }

    @Test
    public void shouldConvertBase64EncodedStringToByteArray() {
        final byte[] bytes = GenericCipherUtils.base64EncodedToBytes(STRING_HELLOWORLD_AS_BASE64);
        assertThat(bytes, is(equalTo(BYTEARRAY_HELLOWORLD)));
    }

}
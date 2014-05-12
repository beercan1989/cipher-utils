package co.uk.baconi.provider.vs.custom.utils;

import java.io.UnsupportedEncodingException;

public final class TestUtil {
    
    private static final String UTF8 = "UTF8";
    
    private TestUtil() {
    }
    
    public static byte[] toBytes(final String string) {
        try {
            return string.getBytes(UTF8);
        } catch (final UnsupportedEncodingException e) {
            throw new AssertionError("UnsupportedEncodingException [" + UTF8 + "]");
        }
    }
}

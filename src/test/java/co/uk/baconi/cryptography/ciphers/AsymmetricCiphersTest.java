package co.uk.baconi.cryptography.ciphers;

import static co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCiphers.RSA_PKCS1;
import static co.uk.baconi.cryptography.utils.CipherUtils.base64EncodedStringToBytes;
import static co.uk.baconi.cryptography.utils.CipherUtils.byteToString;
import static co.uk.baconi.cryptography.utils.CipherUtils.stringToByte;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import co.uk.baconi.cryptography.ciphers.asymmetric.AsymmetricCiphers;

public class AsymmetricCiphersTest {

    private static final String RSA_PKCS12 = "RSA;PKCS1";
    private static final byte[] messageData = stringToByte("HelloWorld.");
    private static final byte[] encryptedData = base64EncodedStringToBytes("h/dy4VV+/AoViHfzSyvelCCrwBc7m8LCc3JVGIin8QXJAoul6cmHloV1EAx4fzfqWkAbpO4OnRTHdq3ul0a425a/qhtZY4CwjHSyH0U255DX6bhVRU/tDzx1yeBVddbmOSV2WgOFxhkT5vBXZK1ziOZ0hehxHkkH9SsknxxgBRKklXtW4v1hCsfVtSiOxqkTBkZ9K1+vF9efQtxZTs7to1fu66mJiYf2H1yaDJ1i1NI0f9sSsk4h3IuyuYGrHi7NLdJj4z7/AYgJ0qGN3aQoUiA4NSqrJqNmGtlXJqAAa/XMJB82z3XA1Wpr4/UzB3HyfahRmlVZEH1WEGFAOogL8Q==");

    private static final byte[] privateKey = base64EncodedStringToBytes("MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC364EZlgh6FitA7MP4qPrzLXdPZLZHuRuII1WNeQ1Ty7yFqOxUg53za6tCOC609RZ/kh8GZjW60EZGL/XH6K0vp0vc2t02c8SCHhwIiUEm7C+rfM1BHidY82aR8fC5hlFda+Mm/2mbZ++57JyIS1Dicdw3uEJpBOjQXav6YEz2nMLhW3gPNXYCzaoYnxP30SDK6LuZViDutlBm7aJAdiI2Pryqte8XQmYZuhg4stA8Rik0W5WzDDv8PXs6I20drqPYP1KQTdBJBIZkDo5cCU/LBcAcV63VziH/mb75UIzKeewkvrQ20fK3DVhxX2wF90hbQYMPN6bg4BV3QA5FJ9A7AgMBAAECggEBAInb+TUYhNoea+WKk4p7/z7wQZI9R3STh9OPyLz2k8rP2EvHxv3Cek7P0dsdCcWSQH73JFJDotqY61QI9w4Vlls152NwmogKVq3Bq/mqCDAIseK09ZVt6MiACc4zr+EgkTSZffbpVFusmMCgXuS6r7JM7mjFsOHPUEN/Mz3FmWrv5+WUTSkp7GOkK68Xzcge02CbfycC+E3TeC7Bze5wEXCWdIl+PAgiaVZeqDyvzObpTNvhuFYs6syKLDqFKgSxiij26CLOUDBQO6xCmh30JkrzzGlYIAKRpLuldYf426ZWtMITvy0XdFROqhK0xyaNHUojC9vbTVNGOCIFpVSs9MECgYEA6ZgQ/wVQql8JToZ+AeAYtXV6ZxkEI9ahd4w9s0o14paXNtnlTf710ISOEJbAmVQcSli0O/0fJD94nH2dg7SJDqyaxAU/BWEAuirb4HyF8M4LsDC3sFyr5r6+IO4cEMzEqw8l60nJ2G4QIH2EzfRNuBzxzDX5/s9bflYXRHFASBkCgYEAyY+vJBDhs8jeWu2vGvkd0B+NTqwgNr9tjcdvz1v8azp46C86s902Cv/rmsLxpLSPaKOBDoBuSUdidLF3xqGZEjU0h2e7tXa4C9x8ythUooKwG1EYvUbYsXW1vEhfjXFS+UoVGWJQXZh00OL/BjxqHIkaLGEtRBoryvhlzkF0dXMCgYEAzO70OkfXdSDbcWDcu5h3FPtz3287CpYKIm+O0fSRQbEMCLsxSTQdREqGuFcJsXrxNuiLdvWilJJ6phAuWJXSiGU1gjN4DqgDk1B2hoO4noKmDnUvMjKbPVyqQQmk5bg/8jLf+YRK6O3miBqWoHlsldIO8DGKmdohUr0EvK7+zkECgYEAxWTXyuRVhbJ0QGyBjlLl5Yrg4mkjazpx2eW1FEgrnf+3pPuL69X6NS+I1xmPeRPzVjC6FS+l0lH8k/exK2/a7r/4X5sxc3d+qu8Vr7nIuRZvzXDQX51gXfq/LlNacLTI46avnxpvRhomXOPRiZPk/2ktnsTUhdtzg+VcHnBv0w0CgYAwu6QJ43zjh8qC6ZQvPy2vpT64Pt1v8iUaA/ZFlzGjfOVrTqlqrIAsX2d5ExrkNzx686j3pVGVKhmlq/Qi7GCEJa2TVNsw8nbb0x9aLFn/sk6ISnPVk2w/G1ANbP9ZGBBhEQKhrIra0ZroU6kbEOlcvzC120NFO0wqangF+7v3mg==");
    private static final byte[] publicKey = base64EncodedStringToBytes("MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAt+uBGZYIehYrQOzD+Kj68y13T2S2R7kbiCNVjXkNU8u8hajsVIOd82urQjgutPUWf5IfBmY1utBGRi/1x+itL6dL3NrdNnPEgh4cCIlBJuwvq3zNQR4nWPNmkfHwuYZRXWvjJv9pm2fvueyciEtQ4nHcN7hCaQTo0F2r+mBM9pzC4Vt4DzV2As2qGJ8T99Egyui7mVYg7rZQZu2iQHYiNj68qrXvF0JmGboYOLLQPEYpNFuVsww7/D17OiNtHa6j2D9SkE3QSQSGZA6OXAlPywXAHFet1c4h/5m++VCMynnsJL60NtHytw1YcV9sBfdIW0GDDzem4OAVd0AORSfQOwIDAQAB");

    @Test
    public void shouldBeAbleToEncryptedMessage() throws InvalidCipherTextException, IOException {
        final byte[] encrypted = RSA_PKCS1.encrypt(privateKey, messageData);

        assertThat(encrypted, is(not(nullValue())));
        assertThat(encrypted, is(equalTo(encryptedData)));
    }

    @Test
    public void shouldBeAbleToDecryptMessage() throws InvalidCipherTextException, IOException {
        final byte[] decrypted = RSA_PKCS1.decrypt(publicKey, encryptedData);

        assertThat(decrypted, is(not(nullValue())));
        assertThat(byteToString(decrypted), is(equalTo(byteToString(messageData))));
    }

    @Test
    public void shouldBeAbleToSerialise() {
        final String stringOne = AsymmetricCiphers.RSA_PKCS1.toString();
        final String stringTwo = AsymmetricCiphers.toString(AsymmetricCiphers.RSA_PKCS1);

        assertThat(stringOne, is(not(nullValue())));
        assertThat(stringOne, is(equalTo(RSA_PKCS12)));

        assertThat(stringTwo, is(not(nullValue())));
        assertThat(stringTwo, is(equalTo(RSA_PKCS12)));
    }

    @Test
    public void shouldBeAbleToDeserialise() throws InvalidCipherTextException, IOException {
        final AsymmetricCiphers fromString = AsymmetricCiphers.fromString(RSA_PKCS12);

        assertThat(fromString, is(not(nullValue())));

        final byte[] encrypted = fromString.encrypt(privateKey, messageData);

        assertThat(encrypted, is(not(nullValue())));
        assertThat(encrypted, is(equalTo(encryptedData)));
    }
}

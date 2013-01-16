package co.uk.baconi.cryptography.ciphers;

import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_SHA256_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_SHA256_TWOFISH_CBC;
import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_SHA512_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_SHA512_TWOFISH_CBC;
import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_WHIRLPOOL_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.pbe.PBECiphers.PBE_WHIRLPOOL_TWOFISH_CBC;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import co.uk.baconi.cryptography.ciphers.pbe.PBECiphers;
import co.uk.baconi.cryptography.testutils.CipherUtils;

public class PBECiphersTest {

    private static final String STRING_PBE_SHA512_AES_CBC = "PBE;SHA512;AES_FAST;CBC";

    private static final char[] password = new char[] { 'p', 'a', 's', 's', 'w', 'o', 'r', 'd' };
    private static final byte[] toEncrypt = CipherUtils.stringToByte("HelloWorld.");

    private static final byte[] salt = CipherUtils.generateBytes(8);
    private static final byte[] iv = CipherUtils.generateBytes(16);

    @BeforeClass
    public static void beforeClass() throws NoSuchAlgorithmException {
        Security.addProvider(new BouncyCastleProvider());
    }

    @Test
    public void shouldBeAbleToRunDoCipher() throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        assertThat(PBE_SHA256_AES_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
        assertThat(PBE_SHA512_AES_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
        assertThat(PBE_WHIRLPOOL_AES_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));

        assertThat(PBE_SHA256_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
        assertThat(PBE_SHA512_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
        assertThat(PBE_WHIRLPOOL_TWOFISH_CBC.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
    }

    @Test
    public void shouldBeAbleToSerialise() {

        final String stringOne = PBE_SHA512_AES_CBC.toString();
        final String stringTwo = PBECiphers.toString(PBE_SHA512_AES_CBC);

        assertThat(stringOne, is(not(nullValue())));
        assertThat(stringOne, is(equalTo(STRING_PBE_SHA512_AES_CBC)));

        assertThat(stringTwo, is(not(nullValue())));
        assertThat(stringTwo, is(equalTo(STRING_PBE_SHA512_AES_CBC)));
    }

    @Test
    public void shouldBeAbleToDeserialise() throws InvalidCipherTextException, IOException {
        final PBECiphers fromString = PBECiphers.fromString(STRING_PBE_SHA512_AES_CBC);

        assertThat(fromString, is(not(nullValue())));
        assertThat(fromString.encrypt(password, salt, iv, toEncrypt), is(not(nullValue())));
    }
}

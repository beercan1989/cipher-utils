package co.uk.baconi.cryptography.ciphers;

import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_SHA256_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_SHA256_TWOFISH_CBC;
import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_SHA512_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_SHA512_TWOFISH_CBC;
import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_WHIRLPOOL_AES_CBC;
import static co.uk.baconi.cryptography.ciphers.PBECiphers.PBE_WHIRLPOOL_TWOFISH_CBC;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.security.NoSuchAlgorithmException;
import java.security.Security;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import co.uk.baconi.cryptography.utils.CipherUtils;

public class PBECiphersTest {

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
}

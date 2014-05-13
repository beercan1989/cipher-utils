package co.uk.baconi.cryptography.ciphers;

import static co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCiphers.AES;
import static co.uk.baconi.cryptography.testutils.CipherUtils.base64EncodedStringToBytes;
import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.IOException;

import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.junit.Test;

import co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCiphers;
import co.uk.baconi.cryptography.testutils.CipherUtils;

public class SymmetricCiphersTest {
    
    private static final byte[] TO_ENCRYPT = base64EncodedStringToBytes("SGVsbG9Xb3JsZA==");
    private static final byte[] TO_DECRYPT = base64EncodedStringToBytes("QODHcgA3t+PfaropIDdc8g==");
    private static final byte[] AES_KEY = base64EncodedStringToBytes("x6Ta1/jm84ec4ZYrwNfHFsmunfuF9+2WD7+aEOmo7ho=");
    
    private static final String AES_MEDIUM = "AES_MEDIUM";
    
    @Test
    public void shouldBeAbleToEncryptWithAES() throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        final byte[] encrypted = AES.encrypt(AES_KEY, TO_ENCRYPT);
        
        assertThat(encrypted, is(equalTo(TO_DECRYPT)));
    }
    
    @Test
    public void shouldBeAbleToDencryptWithAES() throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        final byte[] decrypted = AES.decrypt(AES_KEY, TO_DECRYPT);
        
        assertThat(decrypted, is(equalTo(TO_ENCRYPT)));
    }
    
    @Test(expected = IllegalArgumentException.class)
    public void shouldBeUnAbleToUse512BitKey() throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        final byte[] key = CipherUtils.generateBytes(512);
        final byte[] input = CipherUtils.stringToByte("512 bit key");
        
        AES.encrypt(key, input);
    }
    
    @Test
    public void shouldBeAbleToSerialise() {
        final String stringOne = AES.toString();
        final String stringTwo = SymmetricCiphers.toString(AES);
        
        assertThat(stringOne, is(not(nullValue())));
        assertThat(stringOne, is(equalTo(AES_MEDIUM)));
        
        assertThat(stringTwo, is(not(nullValue())));
        assertThat(stringTwo, is(equalTo(AES_MEDIUM)));
    }
    
    @Test
    public void shouldBeAbleToDeserialise() throws InvalidCipherTextException, IOException {
        final SymmetricCiphers fromString = SymmetricCiphers.fromString(AES_MEDIUM);
        assertThat(fromString, is(not(nullValue())));
        
        final byte[] decrypted = fromString.decrypt(AES_KEY, TO_DECRYPT);
        assertThat(decrypted, is(equalTo(TO_ENCRYPT)));
        
        final byte[] encrypted = fromString.encrypt(AES_KEY, TO_ENCRYPT);
        assertThat(encrypted, is(equalTo(TO_DECRYPT)));
    }
}

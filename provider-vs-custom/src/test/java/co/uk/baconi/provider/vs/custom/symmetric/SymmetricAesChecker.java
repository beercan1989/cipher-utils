package co.uk.baconi.provider.vs.custom.symmetric;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.Security;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.BeforeClass;
import org.junit.Test;

import co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCiphers;
import co.uk.baconi.cryptography.utils.SecureRandomUtil;
import co.uk.baconi.provider.vs.custom.utils.TestUtil;

public class SymmetricAesChecker {
    
    private static final byte[] TEST_DATA_TO_ENCRYPT = TestUtil.toBytes("password");
    private static final BouncyCastleProvider BOUNCY_CASTLE = new BouncyCastleProvider();
    private static final SecureRandom SECURE_RANDOM = SecureRandomUtil.getSecureRandom();
    
    private static final byte[] INITAL_SEED = SECURE_RANDOM.generateSeed(16);
    
    @BeforeClass
    public static void beforeAll() {
        Security.addProvider(BOUNCY_CASTLE);
    }
    
    @Test
    public void shouldBeAbleEncryptAes128AndMatch() throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        final int strength = 128;
        
        // Bouncy Castle Light Weight API
        resetSecureRandom();
        final SymmetricCiphers lightWeightApiCipher = SymmetricCiphers.AES_FAST;
        final CipherKeyGenerator lightWeightApiKeyGen = lightWeightApiCipher.getKeyGenerator();
        lightWeightApiKeyGen.init(new KeyGenerationParameters(SECURE_RANDOM, strength));
        final byte[] lightWeightApiKey = lightWeightApiKeyGen.generateKey();
        final byte[] lightWeightApiResult = lightWeightApiCipher.encrypt(lightWeightApiKey, TEST_DATA_TO_ENCRYPT);
        
        // Bouncy Castle via Java API Provider
        resetSecureRandom();
        final KeyGenerator javaApiProviderKeyGen = KeyGenerator.getInstance("AES", BOUNCY_CASTLE);
        javaApiProviderKeyGen.init(strength, SECURE_RANDOM);
        final SecretKey javaApiProviderKey = javaApiProviderKeyGen.generateKey();
        final Cipher javaApiProviderCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BOUNCY_CASTLE);
        javaApiProviderCipher.init(Cipher.ENCRYPT_MODE, javaApiProviderKey);
        
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, javaApiProviderCipher);
        cipherOutputStream.write(TEST_DATA_TO_ENCRYPT);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        final byte[] javaApiProviderResult = outputStream.toByteArray();
        
        // Assertions
        assertThat(lightWeightApiResult, is(not(nullValue())));
        assertThat(javaApiProviderResult, is(not(nullValue())));
        assertThat(lightWeightApiResult, is(equalTo(javaApiProviderResult)));
    }
    
    private void resetSecureRandom() {
        SECURE_RANDOM.setSeed(INITAL_SEED);
    }
}

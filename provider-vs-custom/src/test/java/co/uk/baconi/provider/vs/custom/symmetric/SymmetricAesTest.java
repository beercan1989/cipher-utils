package co.uk.baconi.provider.vs.custom.symmetric;

import static org.hamcrest.Matchers.equalTo;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.hamcrest.Matchers.nullValue;
import static org.junit.Assert.assertThat;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.Field;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.Permission;
import java.security.PermissionCollection;
import java.security.SecureRandom;
import java.security.Security;
import java.util.Map;

import javax.crypto.Cipher;
import javax.crypto.CipherOutputStream;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

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

public class SymmetricAesTest {
    
    private static final String AES = "AES";
    private static final byte[] TEST_DATA_TO_ENCRYPT = TestUtil.toBytes("password");
    private static final BouncyCastleProvider BOUNCY_CASTLE = new BouncyCastleProvider();
    private static final SecureRandom SECURE_RANDOM = SecureRandomUtil.getSecureRandom();
    
    @BeforeClass
    public static void beforeAll() {
        Security.addProvider(BOUNCY_CASTLE);
        
        removeCryptographyRestrictions();
    }
    
    @Test
    public void shouldBeAbleEncryptAes128AndMatch() throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        doCheckBetweenLightWeightApiAndJavaApiProvider(128);
    }
    
    @Test
    public void shouldBeAbleEncryptAes192AndMatch() throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        doCheckBetweenLightWeightApiAndJavaApiProvider(192);
    }
    
    @Test
    public void shouldBeAbleEncryptAes256AndMatch() throws DataLengthException, IllegalStateException, InvalidCipherTextException, NoSuchAlgorithmException,
            NoSuchPaddingException, InvalidKeyException, IOException {
        doCheckBetweenLightWeightApiAndJavaApiProvider(256);
    }
    
    private void doCheckBetweenLightWeightApiAndJavaApiProvider(final int strength) throws NoSuchAlgorithmException, DataLengthException, IllegalStateException,
            InvalidCipherTextException, IOException, InvalidKeyException, NoSuchPaddingException {
        final byte[] lightWeightApiKey = generateLightWeightApiKey(SymmetricCiphers.AES_FAST, strength);
        final SecretKey javaApiProviderKey = generateJavApiProviderKey(AES, strength);
        
        final byte[] lightWeightApiResult1 = doLightWeightAesEncryption(lightWeightApiKey);
        final byte[] javaApiProviderResult1 = doJavaApiProviderEncryption(lightWeightApiKey);
        
        assertThat(lightWeightApiResult1, is(equalTo(javaApiProviderResult1)));
        
        final byte[] lightWeightApiResult2 = doLightWeightAesEncryption(javaApiProviderKey);
        final byte[] javaApiProviderResult2 = doJavaApiProviderEncryption(javaApiProviderKey);
        
        assertThat(lightWeightApiResult2, is(equalTo(javaApiProviderResult2)));
    }
    
    private byte[] doJavaApiProviderEncryption(final SecretKey javaApiProviderKey) throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchPaddingException {
        assertThat(javaApiProviderKey, is(not(nullValue())));
        
        final Cipher javaApiProviderCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", BOUNCY_CASTLE);
        javaApiProviderCipher.init(Cipher.ENCRYPT_MODE, javaApiProviderKey);
        
        final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
        final CipherOutputStream cipherOutputStream = new CipherOutputStream(outputStream, javaApiProviderCipher);
        cipherOutputStream.write(TEST_DATA_TO_ENCRYPT);
        cipherOutputStream.flush();
        cipherOutputStream.close();
        
        final byte[] javaApiProviderResult = outputStream.toByteArray();
        assertThat(javaApiProviderResult, is(not(nullValue())));
        
        return javaApiProviderResult;
    }
    
    private byte[] doJavaApiProviderEncryption(final byte[] lightWeightApiKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException {
        return doJavaApiProviderEncryption(toJavaApiProviderKey(lightWeightApiKey));
    }
    
    private byte[] doLightWeightAesEncryption(final byte[] lightWeightApiKey) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        assertThat(lightWeightApiKey, is(not(nullValue())));
        
        final SymmetricCiphers lightWeightApiCipher = SymmetricCiphers.AES_FAST;
        final byte[] lightWeightApiResult = lightWeightApiCipher.encrypt(lightWeightApiKey, TEST_DATA_TO_ENCRYPT);
        assertThat(lightWeightApiResult, is(not(nullValue())));
        
        return lightWeightApiResult;
    }
    
    private byte[] doLightWeightAesEncryption(final SecretKey javaApiProviderKey) throws DataLengthException, IllegalStateException, InvalidCipherTextException, IOException {
        return doLightWeightAesEncryption(toLightWeightApiKey(javaApiProviderKey));
    }
    
    private SecretKey generateJavApiProviderKey(final String type, final int strength) throws NoSuchAlgorithmException {
        final KeyGenerator javaApiProviderKeyGen = KeyGenerator.getInstance(AES, BOUNCY_CASTLE);
        javaApiProviderKeyGen.init(strength, SECURE_RANDOM);
        final SecretKey javaApiProviderKey = javaApiProviderKeyGen.generateKey();
        
        return javaApiProviderKey;
    }
    
    private byte[] generateLightWeightApiKey(final SymmetricCiphers lightWeightApiCipher, final int strength) {
        final CipherKeyGenerator lightWeightApiKeyGen = lightWeightApiCipher.getKeyGenerator();
        lightWeightApiKeyGen.init(new KeyGenerationParameters(SECURE_RANDOM, strength));
        final byte[] lightWeightApiKey = lightWeightApiKeyGen.generateKey();
        
        return lightWeightApiKey;
    }
    
    private byte[] toLightWeightApiKey(final SecretKey key) {
        return key.getEncoded();
    }
    
    private SecretKey toJavaApiProviderKey(final byte[] key) {
        return new SecretKeySpec(key, AES);
    }
    
    private static void removeCryptographyRestrictions() {
        if (!isRestrictedCryptography()) {
            System.err.println("Cryptography restrictions removal not needed");
            return;
        }
        
        try {
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Class<?> cryptoPermissions = Class.forName("javax.crypto.CryptoPermissions");
            final Class<?> cryptoAllPermission = Class.forName("javax.crypto.CryptoAllPermission");
            
            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            isRestrictedField.set(null, false);
            
            final Field defaultPolicyField = jceSecurity.getDeclaredField("defaultPolicy");
            defaultPolicyField.setAccessible(true);
            final PermissionCollection defaultPolicy = (PermissionCollection) defaultPolicyField.get(null);
            
            final Field perms = cryptoPermissions.getDeclaredField("perms");
            perms.setAccessible(true);
            ((Map<?, ?>) perms.get(defaultPolicy)).clear();
            
            final Field instance = cryptoAllPermission.getDeclaredField("INSTANCE");
            instance.setAccessible(true);
            defaultPolicy.add((Permission) instance.get(null));
            
            System.err.println("Successfully removed cryptography restrictions.");
        } catch (final Exception e) {
            System.err.println("Failed to remove cryptography restrictions [" + e.getMessage() + "].");
        }
    }
    
    private static boolean isRestrictedCryptography() {
        try {
            final Class<?> jceSecurity = Class.forName("javax.crypto.JceSecurity");
            final Field isRestrictedField = jceSecurity.getDeclaredField("isRestricted");
            isRestrictedField.setAccessible(true);
            return isRestrictedField.getBoolean(null);
        } catch (final Exception e) {
            System.err.println("Unable to determin if its restricted or not [" + e.getMessage() + "].");
            return true;
        }
    }
}

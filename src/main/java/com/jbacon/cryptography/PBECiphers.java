package com.jbacon.cryptography;

import static com.jbacon.cryptography.SymmetricCiphers.AES_FAST;
import static com.jbacon.cryptography.SymmetricCiphers.TWOFISH;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

/**
 * This Enum provides easy access to a PBE built with the BouncyCastle
 * lightweight api.
 * 
 * The Ciphers used in the PBE's have been set to 256bit keys, as this
 * is the highest supported key size using the BouncyCastle's lightweight
 * api.
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public enum PBECiphers {

    @Deprecated
    PBE_MD5_AES_CBC(AES_FAST, new MD5Digest()), //
    @Deprecated
    PBE_SHA1_AES_CBC(AES_FAST, new SHA1Digest()), //
    PBE_SHA256_AES_CBC(AES_FAST, new SHA256Digest()), //
    PBE_SHA512_AES_CBC(AES_FAST, new SHA512Digest()), //
    PBE_WHIRLPOOL_AES_CBC(AES_FAST, new WhirlpoolDigest()), //

    @Deprecated
    PBE_MD5_TWOFISH_CBC(TWOFISH, new MD5Digest()), //
    @Deprecated
    PBE_SHA1_TWOFISH_CBC(TWOFISH, new SHA1Digest()), //
    PBE_SHA256_TWOFISH_CBC(TWOFISH, new SHA256Digest()), //
    PBE_SHA512_TWOFISH_CBC(TWOFISH, new SHA512Digest()), //
    PBE_WHIRLPOOL_TWOFISH_CBC(TWOFISH, new WhirlpoolDigest()); //

    private static final int ITERATION_COUNT = 50;

    private final SymmetricCiphers cipherEngine;
    private final ExtendedDigest digestEngine;

    private PBECiphers(final SymmetricCiphers cipherEngine, final ExtendedDigest digestEngine) {
        this.cipherEngine = cipherEngine;
        this.digestEngine = digestEngine;
    }

    public final byte[] encrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.ENCRYPT, password, salt, iv, input);
    }

    public final byte[] decrypt(final char[] password, final byte[] salt, final byte[] iv, final byte[] input)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        return doCipher(CipherMode.DECRYPT, password, salt, iv, input);
    }

    private final byte[] doCipher(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv,
            final byte[] input) throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        CipherValidation.validateInputs(mode, password, salt, iv, input);

        final KeyParameter keyParam = new KeyParameter(generateEncryptionKey(password, salt, ITERATION_COUNT,
                CipherKeySize.KS_256.getKeySize()));
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = cipherEngine.doCipher(CipherMode.ENCRYPT, input, cipherParams);

        return output;
    }

    private final byte[] generateEncryptionKey(final char[] password, final byte[] salt, final int iterationCount,
            final int keySize) {
        final CipherParameters param = makePBEParameters(password, salt, iterationCount, keySize, 128);

        if (param instanceof ParametersWithIV) {
            return ((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey();
        } else {
            return ((KeyParameter) param).getKey();
        }
    }

    private final CipherParameters makePBEParameters(final char[] password, final byte[] salt,
            final int iterationCount, final int keySize, final int ivSize) {
        final PBEParametersGenerator generator = new PKCS12ParametersGenerator(digestEngine);
        final byte[] key = PBEParametersGenerator.PKCS12PasswordToBytes(password);
        CipherParameters param;

        generator.init(key, salt, iterationCount);

        if (ivSize != 0) {
            param = generator.generateDerivedParameters(keySize, ivSize);
        } else {
            param = generator.generateDerivedParameters(keySize);
        }

        for (int i = 0; i != key.length; i++) {
            key[i] = 0;
        }

        return param;
    }
}
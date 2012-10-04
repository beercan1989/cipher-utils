package com.jbacon.cryptography.utils;

import static com.jbacon.cryptography.utils.SymmetricCipherUtils.AES_FAST;
import static com.jbacon.cryptography.utils.SymmetricCipherUtils.TWOFISH;

import javax.crypto.spec.PBEKeySpec;

import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.PBEParametersGenerator;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.generators.PKCS12ParametersGenerator;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;

import com.jbacon.cryptography.CipherKeySize;
import com.jbacon.cryptography.CipherMode;

public enum PasswordBasedCipherUtils {

    PBE_SHA1_AES_CBC(AES_FAST, new SHA1Digest()), //
    PBE_SHA256_AES_CBC(AES_FAST, new SHA256Digest()), //
    PBE_SHA512_AES_CBC(AES_FAST, new SHA512Digest()), //

    PBE_SHA1_TWOFISH_CBC(TWOFISH, new SHA1Digest()), //
    PBE_SHA256_TWOFISH_CBC(TWOFISH, new SHA256Digest()), //
    PBE_SHA512_TWOFISH_CBC(TWOFISH, new SHA512Digest()); //

    private static final int ITERATION_COUNT = 50;

    private final SymmetricCipherUtils cipherEngine;
    private final ExtendedDigest digestEngine;

    private PasswordBasedCipherUtils(final SymmetricCipherUtils cipherEngine, final ExtendedDigest digestEngine) {
        this.cipherEngine = cipherEngine;
        this.digestEngine = digestEngine;
    }

    public final byte[] doCipher(final CipherMode mode, final char[] password, final byte[] salt, final byte[] iv, final byte[] input) throws DataLengthException,
            IllegalStateException, InvalidCipherTextException {
        final PBEKeySpec pbeKeySpecification = new PBEKeySpec(password, salt, ITERATION_COUNT, CipherKeySize.KS_256.getKeySize());
        final KeyParameter keyParam = new KeyParameter(generateEncryptionKey(pbeKeySpecification));
        final CipherParameters cipherParams = new ParametersWithIV(keyParam, iv);

        final byte[] output = cipherEngine.doCipher(CipherMode.ENCRYPT, input, cipherParams);

        return output;
    }

    private final byte[] generateEncryptionKey(final PBEKeySpec pbeKeySpec) {
        if (pbeKeySpec.getSalt() == null) {
            return PBEParametersGenerator.PKCS12PasswordToBytes(pbeKeySpec.getPassword());
        }
        final CipherParameters param = makePBEParameters(pbeKeySpec, pbeKeySpec.getKeyLength(), 128);

        if (param instanceof ParametersWithIV) {
            return ((KeyParameter) ((ParametersWithIV) param).getParameters()).getKey();
        } else {
            return ((KeyParameter) param).getKey();
        }
    }

    private final CipherParameters makePBEParameters(final PBEKeySpec keySpec, final int keySize, final int ivSize) {
        final PBEParametersGenerator generator = new PKCS12ParametersGenerator(digestEngine);
        final byte[] key = PBEParametersGenerator.PKCS12PasswordToBytes(keySpec.getPassword());
        CipherParameters param;

        generator.init(key, keySpec.getSalt(), keySpec.getIterationCount());

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
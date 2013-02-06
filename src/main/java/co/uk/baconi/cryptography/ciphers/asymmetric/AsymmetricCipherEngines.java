package co.uk.baconi.cryptography.ciphers.asymmetric;

import static co.uk.baconi.cryptography.utils.SecureRandomUtil.getSecureRandom;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.ElGamalKeyGenerationParameters;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

enum AsymmetricCipherEngines {
    EL_GAMAL {
        private static final int DEFAULT_KEY_SIZE = 1024;
        private static final int DEFAULT_CERTAINTY = 20;

        @Override
        public AsymmetricBlockCipher getInstance() {
            return new ElGamalEngine();
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
            final ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(getKeyGenerationParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY));
        }

        private ElGamalKeyGenerationParameters getKeyGenerationParameters(final int keySize, final int certainty) {
            final ElGamalParametersGenerator paramGenerator = new ElGamalParametersGenerator();
            paramGenerator.init(keySize, certainty, getSecureRandom());
            return new ElGamalKeyGenerationParameters(getSecureRandom(), paramGenerator.generateParameters());
        }

        public KeyPair generateKeyPair(final int keySize, final int certainty)
                throws InvalidAlgorithmParameterException {
            final org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi generator = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();

            final ElGamalParametersGenerator paramGenerator = new ElGamalParametersGenerator();
            paramGenerator.init(keySize, certainty, getSecureRandom());
            final ElGamalParameters generateParameters = paramGenerator.generateParameters();
            generator.initialize(new ElGamalParameterSpec(generateParameters.getP(), generateParameters.getG()),
                    getSecureRandom());

            return generator.genKeyPair();
        }

        public KeyPair generateKeyPair() {
            return new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi().genKeyPair();
        }
    },

    NACCACHE_STERN {
        private static final int DEFAULT_KEY_SIZE = 1024;
        private static final int DEFAULT_CERTAINTY = 20;
        private static final int DEFAULT_SMALL_PRIME_COUNT = 60;

        @Override
        public AsymmetricBlockCipher getInstance() {
            return new NaccacheSternEngine();
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
            final NaccacheSternKeyPairGenerator keyPairGenerator = new NaccacheSternKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(new NaccacheSternKeyGenerationParameters(getSecureRandom(), DEFAULT_KEY_SIZE,
                    DEFAULT_CERTAINTY, DEFAULT_SMALL_PRIME_COUNT));
        }
    },

    RSA {
        private static final int DEFAULT_KEY_SIZE = 2048;
        private static final int DEFAULT_CERTAINTY = 20;
        private final BigInteger DEFAULT_PUBLIC_EXPONENT = BigInteger.valueOf(0x10001);

        @Override
        public AsymmetricBlockCipher getInstance() {
            return new RSAEngine();
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
            final RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public AsymmetricCipherKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(new RSAKeyGenerationParameters(DEFAULT_PUBLIC_EXPONENT, getSecureRandom(),
                    DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY));
        }

        public void getGenerator() {
            new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi();
        }
    };

    public abstract AsymmetricBlockCipher getInstance();

    public abstract AsymmetricCipherKeyPairGenerator getKeyGenerator();

    public abstract AsymmetricCipherKeyPairGenerator getKeyGenerator(KeyGenerationParameters params);
}
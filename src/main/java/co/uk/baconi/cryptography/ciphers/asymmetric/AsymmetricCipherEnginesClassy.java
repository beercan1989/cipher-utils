package co.uk.baconi.cryptography.ciphers.asymmetric;

import java.math.BigInteger;
import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
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
import org.bouncycastle.crypto.params.NaccacheSternKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;

public abstract class AsymmetricCipherEnginesClassy<Eingine extends AsymmetricBlockCipher, KeyPairGenerator extends AsymmetricCipherKeyPairGenerator, KeyPairParams extends KeyGenerationParameters> {

    private static final String SECURE_RANDOM_PROVIDER = "SUN";
    private static final String SECURE_RANDOM_IMPL = "SHA1PRNG";

    private static final Log LOG = LogFactory.getLog(AsymmetricCipherEnginesClassy.class);

    public static final AsymmetricCipherEnginesClassy<ElGamalEngine, ElGamalKeyPairGenerator, ElGamalKeyGenerationParameters> EL_GAMAL = new AsymmetricCipherEnginesClassy<ElGamalEngine, ElGamalKeyPairGenerator, ElGamalKeyGenerationParameters>() {
        private static final int DEFAULT_KEY_SIZE = 1024;
        private static final int DEFAULT_CERTAINTY = 20;

        @Override
        public ElGamalEngine getInstance() {
            return new ElGamalEngine();
        }

        @Override
        public ElGamalKeyPairGenerator getKeyGenerator(final ElGamalKeyGenerationParameters params) {
            final ElGamalKeyPairGenerator keyPairGenerator = new ElGamalKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public ElGamalKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(getKeyGenerationParameters(DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY));
        }

        private ElGamalKeyGenerationParameters getKeyGenerationParameters(final int keySize, final int certainty) {
            final ElGamalParametersGenerator paramGenerator = new ElGamalParametersGenerator();
            paramGenerator.init(keySize, certainty, getSecureRandom());
            return new ElGamalKeyGenerationParameters(getSecureRandom(), paramGenerator.generateParameters());
        }
    };

    public static final AsymmetricCipherEnginesClassy<NaccacheSternEngine, NaccacheSternKeyPairGenerator, NaccacheSternKeyGenerationParameters> NACCACHE_STERN = new AsymmetricCipherEnginesClassy<NaccacheSternEngine, NaccacheSternKeyPairGenerator, NaccacheSternKeyGenerationParameters>() {
        private static final int DEFAULT_KEY_SIZE = 1024;
        private static final int DEFAULT_CERTAINTY = 20;
        private static final int DEFAULT_SMALL_PRIME_COUNT = 60;

        @Override
        public NaccacheSternEngine getInstance() {
            return new NaccacheSternEngine();
        }

        @Override
        public NaccacheSternKeyPairGenerator getKeyGenerator(final NaccacheSternKeyGenerationParameters params) {
            final NaccacheSternKeyPairGenerator keyPairGenerator = new NaccacheSternKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public NaccacheSternKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(new NaccacheSternKeyGenerationParameters(getSecureRandom(), DEFAULT_KEY_SIZE,
                    DEFAULT_CERTAINTY, DEFAULT_SMALL_PRIME_COUNT));
        }
    };

    public static final AsymmetricCipherEnginesClassy<RSAEngine, RSAKeyPairGenerator, RSAKeyGenerationParameters> RSA = new AsymmetricCipherEnginesClassy<RSAEngine, RSAKeyPairGenerator, RSAKeyGenerationParameters>() {
        private static final int DEFAULT_KEY_SIZE = 2048;
        private static final int DEFAULT_CERTAINTY = 20;
        private final BigInteger DEFAULT_PUBLIC_EXPONENT = BigInteger.valueOf(0x10001);

        @Override
        public RSAEngine getInstance() {
            return new RSAEngine();
        }

        @Override
        public RSAKeyPairGenerator getKeyGenerator(final RSAKeyGenerationParameters params) {
            final RSAKeyPairGenerator keyPairGenerator = new RSAKeyPairGenerator();
            keyPairGenerator.init(params);
            return keyPairGenerator;
        }

        @Override
        public RSAKeyPairGenerator getKeyGenerator() {
            return getKeyGenerator(new RSAKeyGenerationParameters(DEFAULT_PUBLIC_EXPONENT, getSecureRandom(),
                    DEFAULT_KEY_SIZE, DEFAULT_CERTAINTY));
        }
    };

    private AsymmetricCipherEnginesClassy() {
    }

    public abstract Eingine getInstance();

    public abstract KeyPairGenerator getKeyGenerator(KeyPairParams params);

    public abstract KeyPairGenerator getKeyGenerator();

    private static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance(SECURE_RANDOM_IMPL, SECURE_RANDOM_PROVIDER);
        } catch (final Throwable t) {
            LOG.error("Unable to find prefered SecureRandom implementation, using potentially bad one", t);
        }
        return new SecureRandom();
    }
}
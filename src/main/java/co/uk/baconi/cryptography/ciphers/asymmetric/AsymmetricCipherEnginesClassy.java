package co.uk.baconi.cryptography.ciphers.asymmetric;

import static co.uk.baconi.cryptography.utils.SecureRandomUtil.getSecureRandom;

import java.math.BigInteger;

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

/**
 * @deprecated Use {@link AsymmetricCipherEngines} instead.
 */
@Deprecated
abstract class AsymmetricCipherEnginesClassy<E extends AsymmetricBlockCipher, G extends AsymmetricCipherKeyPairGenerator> {

    private static final String RSA_NAME = "RSA";
    private static final String NACCACHE_STERN_NAME = "NaccacheStern";
    private static final String EL_GAMAL_NAME = "ElGamal";

    public static final AsymmetricCipherEnginesClassy<ElGamalEngine, ElGamalKeyPairGenerator> EL_GAMAL = new AsymmetricCipherEnginesClassy<ElGamalEngine, ElGamalKeyPairGenerator>(
            EL_GAMAL_NAME) {
        public static final int DEFAULT_KEY_SIZE = 1024;
        public static final int DEFAULT_CERTAINTY = 20;

        @Override
        public ElGamalEngine getInstance() {
            return new ElGamalEngine();
        }

        @Override
        public ElGamalKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
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

    public static final AsymmetricCipherEnginesClassy<NaccacheSternEngine, NaccacheSternKeyPairGenerator> NACCACHE_STERN = new AsymmetricCipherEnginesClassy<NaccacheSternEngine, NaccacheSternKeyPairGenerator>(
            NACCACHE_STERN_NAME) {
        public static final int DEFAULT_KEY_SIZE = 1024;
        public static final int DEFAULT_CERTAINTY = 20;
        public static final int DEFAULT_SMALL_PRIME_COUNT = 60;

        @Override
        public NaccacheSternEngine getInstance() {
            return new NaccacheSternEngine();
        }

        @Override
        public NaccacheSternKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
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

    public static final AsymmetricCipherEnginesClassy<RSAEngine, RSAKeyPairGenerator> RSA = new AsymmetricCipherEnginesClassy<RSAEngine, RSAKeyPairGenerator>(
            RSA_NAME) {
        public static final int DEFAULT_KEY_SIZE = 2048;
        public static final int DEFAULT_CERTAINTY = 20;
        public final BigInteger DEFAULT_PUBLIC_EXPONENT = BigInteger.valueOf(0x10001);

        @Override
        public RSAEngine getInstance() {
            return new RSAEngine();
        }

        @Override
        public RSAKeyPairGenerator getKeyGenerator(final KeyGenerationParameters params) {
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

    private final String asymmetricCipherEngineName;

    private AsymmetricCipherEnginesClassy(final String asymmetricCipherEngineName) {
        this.asymmetricCipherEngineName = asymmetricCipherEngineName;
    }

    public String name() {
        return asymmetricCipherEngineName;
    }

    public abstract E getInstance();

    public abstract G getKeyGenerator(KeyGenerationParameters params);

    public abstract G getKeyGenerator();
}
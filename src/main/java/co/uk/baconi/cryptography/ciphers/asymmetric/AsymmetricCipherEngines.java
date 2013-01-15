package co.uk.baconi.cryptography.ciphers.asymmetric;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPairGenerator;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.ElGamalKeyPairGenerator;
import org.bouncycastle.crypto.generators.NaccacheSternKeyPairGenerator;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;

public enum AsymmetricCipherEngines {
    EL_GAMAL {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new ElGamalEngine();
        }

        @Override
        public ElGamalKeyPairGenerator getKeyGenerator() {
            return new ElGamalKeyPairGenerator();
        }
    },

    NACCACHE_STERN {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new NaccacheSternEngine();
        }

        @Override
        public NaccacheSternKeyPairGenerator getKeyGenerator() {
            return new NaccacheSternKeyPairGenerator();
        }
    },

    RSA {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new RSAEngine();
        }

        @Override
        public RSAKeyPairGenerator getKeyGenerator() {
            return new RSAKeyPairGenerator();
        }
    };

    public abstract AsymmetricBlockCipher getInstance();

    public abstract AsymmetricCipherKeyPairGenerator getKeyGenerator();
}
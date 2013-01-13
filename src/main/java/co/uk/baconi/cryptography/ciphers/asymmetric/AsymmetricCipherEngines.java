package co.uk.baconi.cryptography.ciphers.asymmetric;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;

enum AsymmetricCipherEngines {
    EL_GAMAL {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new ElGamalEngine();
        }
    },

    NACCACHE_STERN {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new NaccacheSternEngine();
        }
    },

    RSA {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new RSAEngine();
        }
    };

    public abstract AsymmetricBlockCipher getInstance();
}
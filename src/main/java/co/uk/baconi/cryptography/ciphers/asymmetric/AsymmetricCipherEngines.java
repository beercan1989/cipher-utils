package co.uk.baconi.cryptography.ciphers.asymmetric;

import java.security.KeyPairGenerator;

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

        @Override
        public KeyPairGenerator getKeyPairGenerator() {
            return new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        }
    },

    NACCACHE_STERN {
        private static final String UNSUPPORTED_ERROR = "NaccacheSternEngine does not have a KeyPairGenerator implemented.";

        @Override
        public AsymmetricBlockCipher getInstance() {
            return new NaccacheSternEngine();
        }

        @Override
        public KeyPairGenerator getKeyPairGenerator() {
            throw new UnsupportedOperationException(UNSUPPORTED_ERROR);
        }
    },

    RSA {
        @Override
        public AsymmetricBlockCipher getInstance() {
            return new RSAEngine();
        }

        @Override
        public KeyPairGenerator getKeyPairGenerator() {
            return new org.bouncycastle.jcajce.provider.asymmetric.rsa.KeyPairGeneratorSpi();
        }
    };

    public abstract AsymmetricBlockCipher getInstance();

    public abstract KeyPairGenerator getKeyPairGenerator();
}
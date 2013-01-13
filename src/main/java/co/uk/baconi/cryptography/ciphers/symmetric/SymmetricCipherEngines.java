package co.uk.baconi.cryptography.ciphers.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;

public enum SymmetricCipherEngines {
    AES_FAST {
        @Override
        public BlockCipher getInstance() {
            return new AESFastEngine();
        }
    },

    AES_MEDIUM {
        @Override
        public BlockCipher getInstance() {
            return new AESEngine();
        }
    },

    AES_SLOW {
        @Override
        public BlockCipher getInstance() {
            return new AESLightEngine();
        }
    },

    TWOFISH {
        @Override
        public BlockCipher getInstance() {
            return new TwofishEngine();
        }
    };

    public abstract BlockCipher getInstance();
}
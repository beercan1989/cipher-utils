package co.uk.baconi.cryptography.ciphers.symmetric;

import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.DESEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.generators.DESKeyGenerator;
import org.bouncycastle.crypto.modes.CBCBlockCipher;

public enum SymmetricCipherEngines {
    @Deprecated
    DES {
        @Override
        public BlockCipher getInstance() {
            return new DESEngine();
        }
        
        @Override
        public CipherKeyGenerator getKeyGenerator() {
            return new DESKeyGenerator();
        }
    },
    
    AES_FAST {
        @Override
        public BlockCipher getInstance() {
            return new CBCBlockCipher(new AESFastEngine());
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
    
    public CipherKeyGenerator getKeyGenerator() {
        return new CipherKeyGenerator();
    }
}
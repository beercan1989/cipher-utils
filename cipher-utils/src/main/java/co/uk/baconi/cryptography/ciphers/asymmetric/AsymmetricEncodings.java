package co.uk.baconi.cryptography.ciphers.asymmetric;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.encodings.ISO9796d1Encoding;
import org.bouncycastle.crypto.encodings.OAEPEncoding;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;

enum AsymmetricEncodings {
    OAEP {
        @Override
        public AsymmetricBlockCipher getInstance(final AsymmetricBlockCipher cipherEngine) {
            return new OAEPEncoding(cipherEngine);
        }
    },

    PKCS1 {
        @Override
        public AsymmetricBlockCipher getInstance(final AsymmetricBlockCipher cipherEngine) {
            return new PKCS1Encoding(cipherEngine);
        }
    },

    ISO9796D1 {
        @Override
        public AsymmetricBlockCipher getInstance(final AsymmetricBlockCipher cipherEngine) {
            return new ISO9796d1Encoding(cipherEngine);
        }
    };

    public abstract AsymmetricBlockCipher getInstance(final AsymmetricBlockCipher cipherEngine);
}
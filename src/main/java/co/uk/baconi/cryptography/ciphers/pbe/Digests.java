package co.uk.baconi.cryptography.ciphers.pbe;

import org.bouncycastle.crypto.ExtendedDigest;
import org.bouncycastle.crypto.digests.MD5Digest;
import org.bouncycastle.crypto.digests.SHA1Digest;
import org.bouncycastle.crypto.digests.SHA256Digest;
import org.bouncycastle.crypto.digests.SHA512Digest;
import org.bouncycastle.crypto.digests.WhirlpoolDigest;

enum Digests {
    @Deprecated
    MD5 {
        @Override
        public ExtendedDigest getInstance() {
            return new MD5Digest();
        }
    },

    @Deprecated
    SHA1 {
        @Override
        public ExtendedDigest getInstance() {
            return new SHA1Digest();
        }
    },

    SHA256 {
        @Override
        public ExtendedDigest getInstance() {
            return new SHA256Digest();
        }
    },

    SHA512 {
        @Override
        public ExtendedDigest getInstance() {
            return new SHA512Digest();
        }
    },

    WHIRLPOOL {
        @Override
        public ExtendedDigest getInstance() {
            return new WhirlpoolDigest();
        }
    };

    public abstract ExtendedDigest getInstance();
}
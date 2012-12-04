package com.jbacon.cryptography.ciphers;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.ElGamalEngine;
import org.bouncycastle.crypto.engines.NaccacheSternEngine;
import org.bouncycastle.crypto.engines.RSAEngine;

/**
 * This class provides easy access to certain Asymmetric Ciphers available in BouncyCastle's lightweight api.<br />
 * <br />
 * Please Note:<br />
 * 
 * @author JBacon
 * @version 0.0.1-SNAPSHOT
 */
public final class AsymmetricCiphers {
    public static final AsymmetricCiphers ELGAMAL = new AsymmetricCiphers(new ElGamalEngine());
    public static final AsymmetricCiphers NACCACHE_STERN = new AsymmetricCiphers(new NaccacheSternEngine());
    public static final AsymmetricCiphers RSA = new AsymmetricCiphers(new RSAEngine());

    private final AsymmetricBlockCipher cipherEngine;

    private AsymmetricCiphers(final AsymmetricBlockCipher cipherEngine) {
        this.cipherEngine = cipherEngine;
    }
}
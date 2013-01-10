package com.jbacon.cryptography.ciphers;

import java.util.Arrays;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.BlockCipher;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.engines.AESFastEngine;
import org.bouncycastle.crypto.engines.AESLightEngine;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;

import com.jbacon.cryptography.ciphers.errors.UnsupportedCipherEngine;

abstract class AbstractCiphers {

    protected static enum CipherMode {
        ENCRYPT, //
        DECRYPT; //
    }

    protected static enum CipherEngine {
        AESFast, //
        AESMedium, //
        AESSlow, //
        Twofish; //

        protected BlockCipher getInstance() throws UnsupportedCipherEngine {
            switch (this) {
            case AESFast:
                return new AESFastEngine();
            case AESMedium:
                return new AESEngine();
            case AESSlow:
                return new AESLightEngine();
            case Twofish:
                return new TwofishEngine();
            default:
                throw new UnsupportedCipherEngine("Cipher engine not supported.");
            }
        }
    }

    private static final Log LOG = LogFactory.getLog(AbstractCiphers.class);

    private final CipherEngine cipherEngine;

    protected AbstractCiphers(final CipherEngine cipherEngine) {
        this.cipherEngine = cipherEngine;
    }

    protected final byte[] doCipher(final CipherMode mode, final byte[] input, final CipherParameters cipherParams)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException, UnsupportedCipherEngine {
        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Mode [");
            sb.append(mode);
            sb.append("], Input [");
            sb.append(Arrays.toString(input));
            sb.append("], Cipher Parameters [");
            sb.append(cipherParams);
            sb.append("], Cipher Engine [");
            sb.append(cipherEngine);
            sb.append("]");
            LOG.debug(sb.toString());
        }

        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(cipherEngine.getInstance());
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        cipher.reset();
        cipher.init(CipherMode.ENCRYPT.equals(mode), cipherParams);

        final byte[] outputBuffer = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, outputBuffer, 0);
        length += cipher.doFinal(outputBuffer, length);

        final byte[] output = new byte[length];
        System.arraycopy(outputBuffer, 0, output, 0, length);

        return output;
    }

    protected static final void validateInputs(final byte[] key, final byte[] input) {
        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Key [");
            sb.append(Arrays.toString(key));
            sb.append("], Input [");
            sb.append(Arrays.toString(input));
            sb.append("]");
            LOG.debug(sb.toString());
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }
    }

    protected static final void validateInputs(final char[] password, final byte[] salt, final byte[] iv,
            final byte[] input) {
        if (LOG.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Password [");
            sb.append(mask(password.length));
            sb.append("], Salt [");
            sb.append(Arrays.toString(salt));
            sb.append("], Initialisation Vector [");
            sb.append(Arrays.toString(iv));
            sb.append("], Input [");
            sb.append(Arrays.toString(input));
            sb.append("]");
            LOG.debug(sb.toString());
        }

        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }

        if (salt == null) {
            throw new NullPointerException("Provided salt was null.");
        }

        if (iv == null) {
            throw new NullPointerException("Provided initialization vector was null.");
        }

        if (password == null) {
            throw new NullPointerException("Provided password was null.");
        }
    }

    private static StringBuilder mask(final long length) {
        final StringBuilder sb = new StringBuilder();
        for (int i = 0; i < length; i++) {
            sb.append("*");
        }
        return sb;
    }
}

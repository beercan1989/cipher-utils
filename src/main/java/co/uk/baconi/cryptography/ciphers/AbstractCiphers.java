package co.uk.baconi.cryptography.ciphers;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.bouncycastle.crypto.BufferedBlockCipher;
import org.bouncycastle.crypto.CipherParameters;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.util.encoders.Base64;

import co.uk.baconi.cryptography.ciphers.symmetric.SymmetricCipherEngines;

public abstract class AbstractCiphers {

    private final Log logger = LogFactory.getLog(getClass());

    private final SymmetricCipherEngines symmetricCipherEngine;

    protected AbstractCiphers(final SymmetricCipherEngines symmetricCipherEngine) {
        this.symmetricCipherEngine = symmetricCipherEngine;
    }

    protected final byte[] doCipher(final CipherMode mode, final byte[] input, final CipherParameters cipherParams)
            throws DataLengthException, IllegalStateException, InvalidCipherTextException {
        // XXX - Remove
        // TODO - Remove
        if (logger.isDebugEnabled()) {
            final StringBuilder sb = new StringBuilder();
            sb.append("Mode [");
            sb.append(mode);
            sb.append("], Input [");
            sb.append(new String(Base64.encode(input)));
            sb.append("], Cipher Parameters [");
            sb.append(cipherParams);
            sb.append("], Cipher Engine [");
            sb.append(symmetricCipherEngine);
            sb.append("]");
            logger.debug(sb.toString());
        }

        final CBCBlockCipher cbcBlockCipher = new CBCBlockCipher(symmetricCipherEngine.getInstance());
        final BufferedBlockCipher cipher = new PaddedBufferedBlockCipher(cbcBlockCipher);

        cipher.reset();
        cipher.init(mode.isEncrypt(), cipherParams);

        final byte[] outputBuffer = new byte[cipher.getOutputSize(input.length)];
        int length = cipher.processBytes(input, 0, input.length, outputBuffer, 0);
        length += cipher.doFinal(outputBuffer, length);

        final byte[] output = new byte[length];
        System.arraycopy(outputBuffer, 0, output, 0, length);

        return output;
    }

    protected static final void validateInputs(final byte[] key, final byte[] input) {
        if (input == null) {
            throw new NullPointerException("Provided cipher input was null.");
        }

        if (key == null) {
            throw new NullPointerException("Provided cipher key was null.");
        }
    }

    protected static final void validateInputs(final char[] password, final byte[] salt, final byte[] iv,
            final byte[] input) {
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

    protected final SymmetricCipherEngines getCipherEngine() {
        return symmetricCipherEngine;
    }
}

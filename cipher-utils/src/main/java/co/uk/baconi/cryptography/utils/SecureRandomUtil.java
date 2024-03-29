package co.uk.baconi.cryptography.utils;

import java.security.SecureRandom;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

public final class SecureRandomUtil {
    
    private static final String SECURE_RANDOM_PROVIDER = "SUN";
    private static final String SECURE_RANDOM_IMPL = "SHA1PRNG";
    
    private static final String UNABLE_TO_GET_WANTED_PROVIDER_MESSAGE = "Unable to find prefered SecureRandom implementation, using potentially bad one";
    
    private static final Log LOG = LogFactory.getLog(SecureRandomUtil.class);
    
    private SecureRandomUtil() {
    }
    
    public static SecureRandom getSecureRandom() {
        try {
            return SecureRandom.getInstance(SECURE_RANDOM_IMPL, SECURE_RANDOM_PROVIDER);
        } catch (final Exception e) {
            LOG.error(UNABLE_TO_GET_WANTED_PROVIDER_MESSAGE, e);
        }
        return new SecureRandom();
    }
}

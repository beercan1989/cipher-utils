package co.uk.baconi.cryptography.ciphers;

public enum CipherMode {
    ENCRYPT(true), //
    DECRYPT(false); //

    private final boolean encrypt;

    private CipherMode(final boolean flag) {
        this.encrypt = flag;
    }

    public boolean isEncrypt() {
        return encrypt;
    }
}
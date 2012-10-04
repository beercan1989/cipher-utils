package com.jbacon.cryptography;

public enum CipherKeySize {
    KS_128(128), //
    KS_192(192), //
    KS_256(256), //
    KS_320(320), //
    KS_512(512), //
    KS_1024(1024), //
    KS_2048(2048);

    private int keySize;

    private CipherKeySize(final int keySize) {
        this.keySize = keySize;
    }

    public final int getKeySize() {
        return keySize;
    }
}
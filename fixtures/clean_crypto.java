package com.lab.app.net;
import java.security.SecureRandom;
public class CryptoFile {
    public byte[] hash(byte[] in) throws Exception {
        java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
        return md.digest(in);
    }
}

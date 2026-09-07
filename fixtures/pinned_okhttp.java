package com.lab.app.net;
import okhttp3.CertificatePinner;
public class SecureApi {
    static final String HOST = "api.lab.example.com";
    public static CertificatePinner build() {
        return new CertificatePinner.Builder()
            .add(HOST, "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
            .add(HOST, "sha256/BBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBBB=")
            .build();
    }
}

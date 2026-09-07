package com.lab.app.net;
import javax.net.ssl.X509TrustManager;
public class OpenApi {
    public X509TrustManager get() {
        return new X509TrustManager() {
            public void checkServerTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public void checkClientTrusted(java.security.cert.X509Certificate[] c, String a) {}
            public java.security.cert.X509Certificate[] getAcceptedIssuers() { return new java.security.cert.X509Certificate[0]; }
        };
    }
}

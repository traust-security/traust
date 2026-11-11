import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Random;
import java.util.concurrent.ThreadLocalRandom;
import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLSession;
import javax.net.ssl.X509TrustManager;

class CryptographyTests {

    void weakAlgorithms() throws Exception {
        // ruleid: traust-java-cryptography-weak-algorithm
        Cipher.getInstance("DES");
        // ruleid: traust-java-cryptography-weak-algorithm
        Cipher.getInstance("DESede/CBC/PKCS5Padding");
        // ruleid: traust-java-cryptography-weak-algorithm
        Cipher.getInstance("AES/ECB/PKCS5Padding");
        // ruleid: traust-java-cryptography-weak-algorithm
        MessageDigest.getInstance("MD5");
        // ruleid: traust-java-cryptography-weak-algorithm
        MessageDigest.getInstance("SHA-1");
        // ruleid: traust-java-cryptography-weak-algorithm
        Mac.getInstance("HmacMD5");

        // ok: traust-java-cryptography-weak-algorithm
        Cipher.getInstance("AES/GCM/NoPadding");
        // ok: traust-java-cryptography-weak-algorithm
        MessageDigest.getInstance("SHA-256");
    }

    void weakRandom() {
        // ruleid: traust-java-cryptography-weak-random
        Random r = new Random();
        // ruleid: traust-java-cryptography-weak-random
        Random seeded = new Random(42L);
        // ruleid: traust-java-cryptography-weak-random
        double d = Math.random();
        // ruleid: traust-java-cryptography-weak-random
        int n = ThreadLocalRandom.current().nextInt();

        // ok: traust-java-cryptography-weak-random
        SecureRandom sr = new SecureRandom();
    }

    static class TrustAll implements X509TrustManager {
        // ruleid: traust-java-cryptography-trust-all-tls
        public void checkServerTrusted(X509Certificate[] chain, String authType) { }
        // ruleid: traust-java-cryptography-trust-all-tls
        public void checkClientTrusted(X509Certificate[] chain, String authType) { }
        public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
    }

    void hostnames(HttpsURLConnection conn) {
        // ruleid: traust-java-cryptography-trust-all-tls
        conn.setHostnameVerifier((hostname, session) -> true);
        // ruleid: traust-java-cryptography-trust-all-tls
        HttpsURLConnection.setDefaultHostnameVerifier((hostname, session) -> true);

        // ok: traust-java-cryptography-trust-all-tls
        conn.setHostnameVerifier((hostname, session) -> hostname.equals("api.example.com"));
    }
}

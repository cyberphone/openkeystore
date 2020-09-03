package org.webpki.crypto;

import java.util.Base64;
import java.util.HashMap;

import java.io.ByteArrayInputStream;

import java.math.BigInteger;

import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;

import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;

import java.security.interfaces.XECKey;

import java.security.spec.NamedParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.XECPublicKeySpec;

/*
  This test program verifies that JDK 11 - JDK 15 according to section 3 of
  RFC 8410 incorrectly add an ASN.1 "NULL" to the AlgorithmIdentifier of
  XDH public keys.  See line 9: below.

   0: SEQUENCE
        {
   2:     SEQUENCE
            {
   4:         OBJECT IDENTIFIER X25519 (1.3.101.110)
   9:         NULL
            }
  11:     BIT STRING, 32 bytes
      0000: 2f 97 25 02 da af 6b dc 0e e6 67 39 25 f2 f0 fe   '/.%...k...g9%...'
      0010: 03 b0 24 09 3c f0 fc ef 3c 23 12 46 3d 5c 8e 15   '..$.<...<#.F=\..'
        }
 */
public class Jdk15XdhSerializationBug {
    
    static HashMap<String,Integer> xdhParameters = new HashMap<>();
    
    static {
        xdhParameters.put("X25519", 44);
        xdhParameters.put("X448", 68);
    }
    
    // From RFC 8410
    static String PEM_CERT_WITH_X25519_PUBLIC_KEY =
        "-----BEGIN CERTIFICATE-----" +
        "MIIBLDCB36ADAgECAghWAUdKKo3DMDAFBgMrZXAwGTEXMBUGA1UEAwwOSUVURiBUZX" +
        "N0IERlbW8wHhcNMTYwODAxMTIxOTI0WhcNNDAxMjMxMjM1OTU5WjAZMRcwFQYDVQQD" +
        "DA5JRVRGIFRlc3QgRGVtbzAqMAUGAytlbgMhAIUg8AmJMKdUdIt93LQ+91oNvzoNJj" +
        "ga9OukqY6qm05qo0UwQzAPBgNVHRMBAf8EBTADAQEAMA4GA1UdDwEBAAQEAwIDCDAg" +
        "BgNVHQ4BAQAEFgQUmx9e7e0EM4Xk97xiPFl1uQvIuzswBQYDK2VwA0EAryMB/t3J5v" +
        "/BzKc9dNZIpDmAgs3babFOTQbs+BolzlDUwsPrdGxO3YNGhW7Ibz3OGhhlxXrCe1Cg" +
        "w1AH9efZBw==" +
        "-----END CERTIFICATE-----";
    
    // Assumed to be in "correct" format...
    static String PEM_CERT_WITH_X448_PUBLIC_KEY =
        "-----BEGIN CERTIFICATE-----" +
        "MIIByjCCAS2gAwIBAgIGAXQ5PZs/MAoGCCqGSM49BAMEMBYxFDASBgNVBAMTC1Rlc3QgU3ViIENB" +
        "MB4XDTE4MDEwMTAwMDAwMFoXDTMwMTIzMTIzNTk1OVowNzE1MDMGA1UEAxMsVGVzdCBjZXJ0aWZp" +
        "Y2F0ZSBtYXRjaGluZyB4NDQ4cHJpdmF0ZWtleS5wZW0wQjAFBgMrZW8DOQA2bZT9AKBkUw8Yj42O" +
        "qNO0Dy2TWHDw+9hRcKErIz5wnS1KWK9T26jGRRiu3zsrMy6RWR9KWuKZbaNdMFswCQYDVR0TBAIw" +
        "ADAOBgNVHQ8BAf8EBAMCA/gwHQYDVR0OBBYEFErfb0XFwM4Ph1Q1lvJm+OtMJbkTMB8GA1UdIwQY" +
        "MBaAFKMRZc9dwFCnS+UZ4XZ7VJq3T5eKMAoGCCqGSM49BAMEA4GKADCBhgJBVakq9p47Zer773wb" +
        "lNKMDCsc1T1VEPrQhftjZ5yy9ZfNMNlAr08cIaKHWGEUqwi7agbGhvNrzpBTfrzmbhDVeBACQSVQ" +
        "/F4xbVrgI60vDV9hok0WkpWZPK0ggFTeVHcy8SRBX0winOQn3NLm1OfTytnUZ5LXBmi7LQO8syOn" +
        "rQq0AiJ0" +
        "-----END CERTIFICATE-----";
    
    static String PEM_PUBLIC_X25519_KEY = 
        "-----BEGIN PUBLIC KEY-----" +
        "MCowBQYDK2VuAyEAo16U773QQYaQB4eegNCldg6huoIZLsOQIYkFWvbZ5lA=" +
        "-----END PUBLIC KEY-----";
    
    static String RFC_7748_X25519_PUBLIC_KEY =
        "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f";
    
    public static void main(String[] args) throws Exception {
        for (String keyAlgorithm : xdhParameters.keySet()) {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("XDH");
            kpg.initialize(new NamedParameterSpec(keyAlgorithm));
            KeyPair keyPair = kpg.generateKeyPair();
            checkKey(keyPair.getPublic(), "key generation");
        }

        pemCertTest(PEM_CERT_WITH_X25519_PUBLIC_KEY);
        pemCertTest(PEM_CERT_WITH_X448_PUBLIC_KEY);
        
        pemPublicKeyTest(PEM_PUBLIC_X25519_KEY);
        
        constructedPublicKey(RFC_7748_X25519_PUBLIC_KEY, "X25519");
    }

    static void constructedPublicKey(String rawKeyInHex, String keyAlgorithm) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        checkKey(kf.generatePublic(
                    new XECPublicKeySpec(new NamedParameterSpec(keyAlgorithm),
                                         new BigInteger(rawKeyInHex, 16))),"Constructed key");
        }

    static void pemPublicKeyTest(String pemPublicKey) throws Exception {
        KeyFactory kf = KeyFactory.getInstance("XDH");
        checkKey(kf.generatePublic(
                    new X509EncodedKeySpec(getPemBlob(pemPublicKey, "PUBLIC KEY"))),
                "Public key parsing");
    }

    static void pemCertTest(String pemCert) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate certificate =
                (X509Certificate) cf.generateCertificate(
                        new ByteArrayInputStream(getPemBlob(pemCert, "CERTIFICATE")));
        checkKey(certificate.getPublicKey(), "Certificate parsing");
    }

    private static void checkKey(PublicKey publicKey, String activity) {
        String keyAlgorithm = ((NamedParameterSpec)((XECKey)publicKey).getParams()).getName();
        int actual = publicKey.getEncoded().length;
        int expected = xdhParameters.get(keyAlgorithm);
        if (expected != actual) {
            System.out.println("Failed[activity=" + activity + ", algorithm=" +
                               keyAlgorithm + "]: expected=" + expected + ", actual=" + actual);
        } else {
            System.out.println("Success for activity=" + activity + ", algorithm=" + keyAlgorithm);
        }
    }

    static byte[] getPemBlob(String pemData, String qualifier) {
        String beginTag = "-----BEGIN " + qualifier + "-----";
        return Base64.getDecoder()
                .decode(pemData.substring(pemData.indexOf(beginTag) + beginTag.length(),
                                          pemData.indexOf("-----END " + qualifier + "-----")));
    }
}

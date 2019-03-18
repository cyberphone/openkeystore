package org.webpki.crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

public class ECFun {
    static final byte[] DATA = {0, 6, 3, 4, 67, (byte) 255, (byte) 128};

    static boolean ecdsa_der;

    public static void main(String[] argv) {
        boolean bc = CustomCryptoProvider.conditionalLoad(true);
        do {
            try {
                if (argv.length != 1) {
                    System.exit(3);
                }
                ecdsa_der = new Boolean(argv[0]);
                for (KeyAlgorithms ka : KeyAlgorithms.values()) {
                    if (ka.isECKey() || ka == KeyAlgorithms.RSA1024) {
                        if (ka.getPublicKeySizeInBits() < 256) {
                            continue;
                        }
                        if (!bc && ka == KeyAlgorithms.BRAINPOOL_P_256) {
                            continue;
                        }
                        System.out.println("Alg=" + ka);
                        AlgorithmParameterSpec algParSpec = ka.isRSAKey() ?
                                new RSAKeyGenParameterSpec(ka.getPublicKeySizeInBits(), RSAKeyGenParameterSpec.F4)
                                :
                                new ECGenParameterSpec(ka.getJceName());
                        KeyPairGenerator kpg = KeyPairGenerator.getInstance(ka.isRSAKey() ? "RSA" : "EC");
                        kpg.initialize(algParSpec, new SecureRandom());
                        KeyPair keyPair = kpg.generateKeyPair();
                        PublicKey publicKey = keyPair.getPublic();
                        PrivateKey privateKey = keyPair.getPrivate();
                        for (int i = 0; i < 100; i++) {
                            performOneOp(publicKey, privateKey, ka.isRSAKey() ?
                                    AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256);
                        }
                    }
                }
            } catch (Exception e) {
                System.out.println("Fail" + e.getMessage());
                e.printStackTrace();
                System.exit(3);
            }
        }
        while (true);
    }

    private static void performOneOp(PublicKey publicKey, PrivateKey privateKey, AsymSignatureAlgorithms algorithm) throws Exception {
        SignatureWrapper sign = new SignatureWrapper(algorithm, privateKey).setEcdsaSignatureEncoding(ecdsa_der);
        sign.update(DATA);
        byte[] signature = sign.sign();
        SignatureWrapper ver = new SignatureWrapper(algorithm, publicKey).setEcdsaSignatureEncoding(ecdsa_der);
        ver.update(DATA);
        if (!ver.verify(signature)) {
            throw new Exception("Didn't verify");
        }
    }
}

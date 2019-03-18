/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.crypto;

import java.math.BigInteger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import javax.crypto.KeyAgreement;

import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;

public class KeyExperiments {
    static String provider;

    // Simple test of keys and generation

    private static KeyPair gen(KeyAlgorithms key_alg) throws Exception {
        AlgorithmParameterSpec alg_par_spec = null;
        if (key_alg.isRSAKey()) {
            int rsa_key_size = key_alg.getPublicKeySizeInBits();
            BigInteger exponent = RSAKeyGenParameterSpec.F4;
            if (key_alg.hasParameters()) {
                exponent = RSAKeyGenParameterSpec.F0;
            }
            alg_par_spec = new RSAKeyGenParameterSpec(rsa_key_size, exponent);
        } else {
            alg_par_spec = new ECGenParameterSpec(key_alg.getJceName());
        }
        KeyPairGenerator generator = KeyPairGenerator.getInstance(alg_par_spec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC");
        generator.initialize(alg_par_spec, new SecureRandom());
        KeyPair kp = generator.generateKeyPair();
        if (key_alg != KeyAlgorithms.getKeyAlgorithm(kp.getPublic(), key_alg.hasParameters())) {
            throw new RuntimeException("Key mismatch on: " + key_alg);
        }
        return kp;
    }

    static byte[] data = {4, 5, 6, 7, 8, 0};


    private static String signverify(KeyPair kp, AsymSignatureAlgorithms optional) throws Exception {
        AsymSignatureAlgorithms sign_alg = optional == null ?
                kp.getPublic() instanceof RSAPublicKey ?
                        AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256
                :
                optional;

        byte[] signature = new SignatureWrapper(sign_alg, kp.getPrivate(), provider)
                .update(data)
                .sign();

        if (!new SignatureWrapper(sign_alg, kp.getPublic(), provider)
                .update(data)
                .verify(signature)) {
            throw new RuntimeException("Bad sign for: " + kp.getPublic().toString());
        }
        return new SignatureWrapper(sign_alg, kp.getPrivate(), provider).getProvider().getName();
    }

    private static KeyAgreement getKeyAgreement() throws Exception {
        return provider == null ? KeyAgreement.getInstance("ECDH") : KeyAgreement.getInstance("ECDH", provider);
    }

    private static void execute(KeyAlgorithms key_alg) throws Exception {
        KeyPair kp1 = gen(key_alg);
        KeyPair kp2 = gen(key_alg);
        if (key_alg.isECKey()) {
            KeyAgreement ka1 = getKeyAgreement();

            ka1.init(kp1.getPrivate());

            KeyAgreement ka2 = getKeyAgreement();

            ka2.init(kp2.getPrivate());

            ka1.doPhase(kp2.getPublic(), true);
            ka2.doPhase(kp1.getPublic(), true);

            BigInteger k1 = new BigInteger(ka1.generateSecret());
            BigInteger k2 = new BigInteger(ka2.generateSecret());
            byte[] Z = k2.toByteArray();
            while (Z.length < (key_alg.getPublicKeySizeInBits() + 7) / 8) {
                Z = ArrayUtil.add(new byte[]{0}, Z);
            }

            if (!k1.equals(k2)) {
                throw new RuntimeException(key_alg + " 2-way test failed");
            }
            System.out.println("ECDH worked for key algorithm: " + key_alg);
            System.out.println("\nECPublicKey1=" + Base64URL.encode(kp1.getPublic().getEncoded()) +
                    "\nECPrivateKey1=" + Base64URL.encode(kp1.getPrivate().getEncoded()) +
                    "\nECPublicKey2=" + Base64URL.encode(kp2.getPublic().getEncoded()) +
                    "\nECPrivateKey2=" + Base64URL.encode(kp2.getPrivate().getEncoded()) +
                    "\nZ=" + Base64URL.encode(Z));
        }
        signverify(kp1, null);
        String provider_name = signverify(kp2, key_alg.getRecommendedSignatureAlgorithm());
        System.out.println("Signature worked for algorithm: " + key_alg + ", provider=" + provider_name);
    }

    public static void main(String[] argv) throws Exception {
        try {
            Class<?> clazz = Class.forName("org.bouncycastle.jce.provider.BouncyCastleProvider");
            Security.insertProviderAt((Provider) clazz.newInstance(), 1);
        } catch (Exception e) {
            System.out.println("BC not found");
        }
        if (argv.length == 1) {
            provider = argv[0];
        }
        for (KeyAlgorithms key_alg : KeyAlgorithms.values()) {
            execute(key_alg);
        }
    }
}

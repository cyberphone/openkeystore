/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
package org.webpki.keygen2;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;

import java.security.spec.ECGenParameterSpec;

import java.util.Arrays;
import java.util.LinkedHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

public class SoftHSM implements ServerCryptoInterface {

    ////////////////////////////////////////////////////////////////////////////////////////
    // Private and secret keys would in a HSM implementation be represented as handles
    ////////////////////////////////////////////////////////////////////////////////////////
    LinkedHashMap<PublicKey, PrivateKey> key_management_keys = new LinkedHashMap<>();

    private void addKMK(KeyStore km_keystore) {
        try {
            key_management_keys.put(km_keystore.getCertificate("mykey").getPublicKey(),
                    (PrivateKey) km_keystore.getKey("mykey", DemoKeyStore.getSignerPassword().toCharArray()));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    public SoftHSM() {
        addKMK(DemoKeyStore.getMybankDotComKeyStore());
        addKMK(DemoKeyStore.getSubCAKeyStore());
        addKMK(DemoKeyStore.getECDSAStore());
    }

    ECPrivateKey server_ec_private_key;

    byte[] session_key;
    
    @Override
    public ECPublicKey generateEphemeralKey(KeyAlgorithms ec_key_algorithm) {
        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec(ec_key_algorithm.getJceName());
            generator.initialize(eccgen, new SecureRandom());
            KeyPair kp = generator.generateKeyPair();
            server_ec_private_key = (ECPrivateKey) kp.getPrivate();
            return (ECPublicKey) kp.getPublic();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public void generateAndVerifySessionKey(ECPublicKey client_ephemeral_key,
                                            byte[] kdf_data,
                                            byte[] attestation_arguments,
                                            X509Certificate device_certificate,
                                            byte[] session_attestation) {
        try {
        // SP800-56A C(2, 0, ECC CDH)
        KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
        key_agreement.init(server_ec_private_key);
        key_agreement.doPhase(client_ephemeral_key, true);
        byte[] Z = key_agreement.generateSecret();

        // The custom KDF
        Mac mac = Mac.getInstance(HmacAlgorithms.HMAC_SHA256.getJceName());
        mac.init(new SecretKeySpec(Z, "RAW"));
        session_key = mac.doFinal(kdf_data);

        if (device_certificate == null) {
            // Privacy enabled mode
            mac = Mac.getInstance(HmacAlgorithms.HMAC_SHA256.getJceName());
            mac.init(new SecretKeySpec(session_key, "RAW"));
            byte[] session_key_attest = mac.doFinal(attestation_arguments);

            // Verify that the session key signature is correct
            if (!Arrays.equals(session_key_attest, session_attestation)) {
                throw new CryptoException("Verify attestation failed");
            }
        } else {
            // E2ES mode
            PublicKey device_public_key = device_certificate.getPublicKey();

            // Verify that attestation was signed by the device key
            if (!new SignatureWrapper(device_public_key instanceof RSAKey ?
                                       AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256,
                                      device_public_key)
                    .update(attestation_arguments)
                    .verify(session_attestation)) {
                throw new CryptoException("Verify provisioning signature failed");
            }
        }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
}

    @Override
    public byte[] mac(byte[] data, byte[] key_modifier) {
        return HmacAlgorithms.HMAC_SHA256.digest(ArrayUtil.add(session_key, key_modifier), data);
    }

    @Override
    public byte[] encrypt(byte[] data) {
        try {
            byte[] key = mac(SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] iv = new byte[16];
            new SecureRandom().nextBytes(iv);
            crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
            return ArrayUtil.add(iv, crypt.doFinal(data));
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public byte[] generateNonce() {
        byte[] rnd = new byte[32];
        new SecureRandom().nextBytes(rnd);
        return rnd;
    }

    @Override
    public byte[] generateKeyManagementAuthorization(PublicKey key_management__key, byte[] data) {
        try {
            return new SignatureWrapper(key_management__key instanceof RSAKey ?
                                           AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256,
                                        key_management_keys.get(key_management__key))
                .update(data)
                .sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    @Override
    public PublicKey[] enumerateKeyManagementKeys() {
        return key_management_keys.keySet().toArray(new PublicKey[0]);
    }
}

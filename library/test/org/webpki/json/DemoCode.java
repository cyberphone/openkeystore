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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.spec.ECGenParameterSpec;

import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;

/**
 * Demo code for JDOC
 */
public class DemoCode {
    static {
        CustomCryptoProvider.conditionalLoad(true);
    }

    public void signAndVerifyJCS(final PublicKey publicKey, final PrivateKey privateKey) throws IOException {

        // Create an empty JSON document
        JSONObjectWriter writer = new JSONObjectWriter();

        // Fill it with some data
        writer.setString("myProperty", "Some data");

        // Sign document
        writer.setSignature(new JSONAsymKeySigner(new AsymKeySignerInterface() {
            @Override
            public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                try {
                    return new SignatureWrapper(algorithm, privateKey)
                            .update(data)
                            .sign();
                } catch (GeneralSecurityException e) {
                    throw new IOException(e);
                }
            }

            @Override
            public PublicKey getPublicKey() throws IOException {
                return publicKey;
            }
        }));

        // Serialize document
        String json = writer.toString();

        // Print document on the console
        System.out.println("Signed doc:\n" + json);

        // Parse document
        JSONObjectReader reader = JSONParser.parse(json);

        // Get and verify signature
        JSONSignatureDecoder signature = reader.getSignature(new JSONCryptoHelper.Options());
        signature.verify(new JSONAsymKeyVerifier(publicKey));

        // Print document payload on the console
        System.out.println("Returned data: " + reader.getString("myProperty"));
    }

    public static void main(String[] argc) {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(KeyAlgorithms.NIST_P_256.getJceName()), new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            new DemoCode().signAndVerifyJCS(keyPair.getPublic(), keyPair.getPrivate());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

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
package org.webpki.jose.jws;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.spec.ECGenParameterSpec;

import java.util.Base64.Encoder;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;

public class Benchmark {
    
    static final String JSON_TO_BE_SIGNED =
        "{\n" +
        "  \"statement\": \"Hello signed world!\",\n" +
        "  \"otherProperties\": [2000, true]\n" +
        "}";
    
    static final String SIGNATURE_PROPERTY = "signature";
    
    static final int TURNS = 10000;
    
    static final byte[] SECRET_KEY = HexaDecimal.decode(
                    "7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a");

    public static void main(String[] argc) {
        try {
            JSONObjectReader json = JSONParser.parse(JSON_TO_BE_SIGNED);
            Encoder encoder = java.util.Base64.getUrlEncoder();
            
            byte[] data = json.serializeToBytes(JSONOutputFormats.CANONICALIZED);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec(KeyAlgorithms.P_256.getJceName()),
                               new SecureRandom());
            KeyPair keyPair = kpg.generateKeyPair();
            
            long start = System.currentTimeMillis();
            for (int i = 0; i < TURNS; i++) {
                json.serializeToBytes(JSONOutputFormats.CANONICALIZED);
            }
            long canon = System.currentTimeMillis();
            for (int i = 0; i < TURNS; i++) {
                encoder.encodeToString(data);
 //               Base64URL.encode(data).getBytes("utf-8");
            }
            long b64u = System.currentTimeMillis();
            for (int i = 0; i < TURNS; i++) {
                new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, keyPair.getPrivate())
                .update(data).sign();
            }
            long sign = System.currentTimeMillis();
            data = ArrayUtil.add(data, data);
            for (int i = 0; i < TURNS; i++) {
                new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, keyPair.getPrivate())
                .update(data).sign();
            }
            long sign2 = System.currentTimeMillis();
            System.out.println("JCS=" + (canon-start) +
                               ", B64=" + (b64u-canon) +
                               ", ES256=" + (sign-b64u) +
                               ", ES256*2=" + (sign2-sign));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

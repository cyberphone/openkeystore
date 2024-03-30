/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.json;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.spec.ECGenParameterSpec;

import org.webpki.crypto.KeyAlgorithms;

/**
 * Demo code for JDOC
 */
public class JavaScriptSignature {
    public static void main(String[] argc) throws Exception {

        // Get a key-pair.  Here created one from scratch.
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(KeyAlgorithms.P_256.getJceName()), new SecureRandom());
        final KeyPair keyPair = kpg.generateKeyPair();

        // Create an empty JSON object
        JSONObjectWriter writer = new JSONObjectWriter();

        // Fill it with some data
        writer.setString("device", "Pump2");
        writer.setDouble("value", 1.3e4);

        // Sign object
        writer.setSignature(new JSONAsymKeySigner(keyPair.getPrivate())
                                .setPublicKey(keyPair.getPublic()));

        // Serialize the signed object in JavaScript format
        String javaScript = "var reading = \n" +
                new String(writer.serializeToBytes(JSONOutputFormats.PRETTY_JS_NATIVE), "UTF-8") +
                ";\n";

        // Print object on the console
        System.out.println(javaScript);
    }
}

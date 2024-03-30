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
package org.webpki.jose.jws;

import java.security.KeyPair;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.jose.JOSEKeyWords;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.IO;

public class TestVector {
    
    static final String JSON_TO_BE_SIGNED =
        "{\n" +
        "  \"statement\": \"Hello signed world!\",\n" +
        "  \"otherProperties\": [2000, true]\n" +
        "}";
    
    static final String SIGNATURE_PROPERTY = "signature";
    
    static final int TURNS = 10000;
    
   
    public static void main(String[] argc) {
        try {
            JSONObjectReader jsonIn = JSONParser.parse(JSON_TO_BE_SIGNED);
            
            KeyPair keyPair = JSONParser.parse(IO.readFile(argc[0]))
                .removeProperty(JOSEKeyWords.KID_JSON)
                .getKeyPair(AlgorithmPreferences.JOSE);
            
            JSONObjectWriter jsonOut = new JWSAsymKeySigner(keyPair.getPrivate())
                .sign(new JSONObjectWriter(jsonIn), SIGNATURE_PROPERTY);

            System.out.println("JWS/CT=\n" + jsonOut);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

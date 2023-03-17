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

import org.webpki.crypto.HmacAlgorithms;

import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.HexaDecimal;

public class Demo {
    
    static final String JSON_TO_BE_SIGNED =
        "{\n" +
        "  \"statement\": \"Hello signed world!\",\n" +
        "  \"otherProperties\": [2000, true]\n" +
        "}";
    
    static final String SIGNATURE_PROPERTY = "signature";
    
    static final byte[] SECRET_KEY = HexaDecimal.decode(
            "7fdd851a3b9d2dafc5f0d00030e22b9343900cd42ede4948568a4a2ee655291a");

    public static void main(String[] argc) {
        try {
            JWSHmacSigner signer = new JWSHmacSigner(SECRET_KEY,
                                                     HmacAlgorithms.HMAC_SHA256);
            System.out.println(
                signer.sign(
                        new JSONObjectWriter(JSONParser.parse(JSON_TO_BE_SIGNED)),
                        SIGNATURE_PROPERTY).toString());
/*
{
  "statement": "Hello signed world!",
  "otherProperties": [2000, true],
  "signature": "eyJhbGciOiJIUzI1NiJ9..VHVItCBCb8Q5CI-49imarDtJeSxH2uLU0DhqQP5Zjw4"
} 
 */
           
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

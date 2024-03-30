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
package org.webpki.sks;

import java.security.SecureRandom;

import org.webpki.util.Base64;
import org.webpki.util.HexaDecimal;

public class Random {
    public static void main(String[] argc) {
        if (argc.length != 2 || !(argc[1].equals("hex") || argc[1].equals("b64"))) {
            System.out.println("nr-of-bytes {hex|b64}");
            System.exit(3);
        }
        int n = Integer.parseInt(argc[0]);
        byte[] rnd = new byte[n];
        new SecureRandom().nextBytes(rnd);
        if (argc[1].equals("hex")) {
            System.out.println(HexaDecimal.encode(rnd));
        } else {
            System.out.println(Base64.encode(rnd));
        }
    }
}

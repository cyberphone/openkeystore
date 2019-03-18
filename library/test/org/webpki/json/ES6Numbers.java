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

import java.util.Random;

public class ES6Numbers {
    
    public static void main(String[] argc) {
        if (argc.length != 1) {
            System.out.println("ES6Numbers number-of-turns");
            System.exit(0);
        }
        double d = 0;
        long v = 0;
        long skipped = 0;
        try {
            Random random = new Random();
            long i = Long.parseLong(argc[0]);
            long c = 0;
            while (c++ < i) {
                v = random.nextLong();
                d = Double.longBitsToDouble(v);
                if (Double.isNaN(d) || Double.isInfinite(d)) {
                    skipped++;
                    continue;
                }
                String javaDString = Double.toString(d);
                String jsonDString = NumberToJSON.serializeNumber(d);
                double jsonD = Double.valueOf(jsonDString);
                if (d != jsonD) {
                    System.out.println("javaDString=" + javaDString + ", jsonDString=" + jsonDString + ", long=" + Long.toString(v, 16));
                }
                if (c % (i / 10) == 0) {
                    System.out.println("count=" + c + ", skipped=" + skipped);
                }
            }
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage() + " d=" + d + " v=" + Long.toString(v, 16));
        }
    }
}

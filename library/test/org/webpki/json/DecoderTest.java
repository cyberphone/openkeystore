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

import java.io.IOException;

import org.webpki.util.IO;

public class DecoderTest {
    public static void main(String[] argc) {
        if (argc.length != 4) {
            System.out.println("\nclass-name instance-document test-unread format(" + JSONOutputFormats.NORMALIZED + "|" + JSONOutputFormats.PRETTY_PRINT + ")");
            System.exit(0);
        }
        try {
            for (JSONOutputFormats of : JSONOutputFormats.values()) {
                if (of.toString().equals(argc[3])) {
                    JSONDecoderCache parser = new JSONDecoderCache();
                    parser.setCheckForUnreadProperties(Boolean.valueOf(argc[2]));
                    parser.addToCache(argc[0]);
                    JSONDecoder doc = parser.parse(IO.readFile(argc[1]));
                    System.out.print(new String(doc.getWriter().serializeToBytes(of), "UTF-8"));
                    return;
                }
            }
            throw new IOException("Unknown format: " + argc[3]);
        } catch (Exception e) {
            System.out.println("Error: " + e.getMessage());
            e.printStackTrace();
        }
    }
}

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
package org.webpki.tools;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.Base64;

/**
 * Base64 CLI
 */
public class B64 {

    static void exitCommand() {
        System.out.println("\nUsage:\n\n  org.webpki.util.Base64 [enc|dec|encurl|decurl] <infile> <outfile>\n");
        System.exit(3);
    }

    /**
     * @param args Command line interface
     * @throws Exception If anything unexpected happens...
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            exitCommand();
        } else {
            byte[] output = null;
            byte[] input = ArrayUtil.readFile(args[1]);
            if (args[0].startsWith("dec")) {
                StringBuilder string = new StringBuilder();
                for (byte b : input) {
                    if (b > ' ') {
                        string.append((char) b);
                    }
                }
                if (args[0].equals("dec")) {
                    output = Base64.decode(string.toString());
                } else if (args[0].equals("decurl")) {
                    output = Base64URL.decode(string.toString());
                } else {
                    exitCommand();
                }
            } else if (args[0].equals("enc")) {
                output = Base64.encode(input).getBytes("UTF-8");
            } else if (args[0].equals("encurl")) {
                output = Base64URL.encode(input).getBytes("UTF-8");
            } else {
                exitCommand();
            }
            ArrayUtil.writeFile(args[2], output);
        }
    }
}

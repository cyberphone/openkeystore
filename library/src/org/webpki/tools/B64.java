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
package org.webpki.tools;

import org.webpki.util.Base64URL;
import org.webpki.util.IO;
import org.webpki.util.UTF8;
import org.webpki.util.Base64;

/**
 * Base64 CLI
 */
public class B64 {

    static void show() {
        System.out.println("\n" +
                           "Usage: B64 enc|encurl input-pipe\n" +
                           "           dec|decurl text-argument|input-pipe");
        System.exit(3);
    }

    /**
     * @param args Command line interface
     * @throws Exception If anything unexpected happens...
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0 || args.length > 2) show();
        switch (args[0]) {
            case "enc":
            case "encurl":
                if (args.length == 2) show();
                byte[] toBeEncoded = IO.getByteArrayFromInputStream(System.in);
                System.out.print(args[0].equals("enc") ? 
                            Base64.encode(toBeEncoded) : Base64URL.encode(toBeEncoded));
                break;
                
            case "dec":
            case "decurl":
                String toBeDecoded = args.length == 2 ? 
                        args[1] : UTF8.decode(IO.getByteArrayFromInputStream(System.in))
                                                  .replace(" ", "")
                                                  .replace("\n", "")
                                                  .replace("\r", "");
                System.out.write(args[0].equals("dec") ?
                            Base64.decode(toBeDecoded) : Base64URL.decode(toBeDecoded));
                break;
                
            default:
                show();
        }
    }
}

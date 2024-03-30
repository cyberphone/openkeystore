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

import java.io.IOException;

import org.webpki.util.IO;
import org.webpki.util.HexaDecimal;
import org.webpki.util.UTF8;

/**
 * Encodes/decodes hexadecimal data.
 */
public class Hex {

    private Hex() {}


    /*##################################################################*/
    /*                                                                  */
    /*  Method: main                                                    */
    /*                                                                  */
    /*  Description: This is a command-line interface for testing only  */
    /*                                                                  */
    /*##################################################################*/
    
    static void show() {
        System.out.println("\n" +
                           "Usage: Hex hex|dump input-pipe\n" +
                           "           tobin text-argument-hex|input-pipe-hex");
        System.exit(3);
    }

    public static void main(String[] args) throws IOException {
        if (args.length == 0 || args.length > 2) show();
        switch (args[0]) {
            case "hex":
            case "dump":
                if (args.length == 2) show();
                byte[] data = IO.getByteArrayFromInputStream(System.in);
                System.out.print(args[0].equals("dump") ? 
                      HexaDecimal.getHexDebugData(data, 16) : HexaDecimal.encode(data));
                break;

            case "tobin":
                System.out.write(HexaDecimal.decode(args.length == 2 ? 
                        args[1] : UTF8.decode(IO.getByteArrayFromInputStream(System.in)).trim()));
                break;

            default:
                show();
        }
    }

}

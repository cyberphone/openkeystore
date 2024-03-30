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

import org.webpki.cbor.CBORObject;

import org.webpki.util.IO;
import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.UTF8;

/**
 * Decodes CBOR data.
 */
public class CBORPrinter {


    private CBORPrinter() {}  // No instantiation please

    ///////////////////////////////
    ////       DEBUGGING       ////
    ///////////////////////////////

    static void show() {
        System.out.println("\nUsage: CBORPrinter hex|bin|b64u text-srgument|pipe");
        System.exit(3);
    }

    /**
     * Run CBOR printer.
     * <p>
     * <code>java -cp </code><i>path</i><code>/webpki.org-libext-n.n.n.jar org.webpki.tools.CBORPrinter bin </code><i>CBORfile</i>
     * </p>
     * @param args Command line interface
     * 
     * @throws Exception If anything unexpected happens...
     */
    public static void main(String[] args) throws Exception {
        if (args.length == 0) {
            show();
        }
        byte[] readCbor = args.length == 1 ? 
                IO.getByteArrayFromInputStream(System.in) : UTF8.encode(args[1]);
        String format = args[0];
        if (!format.equals("bin")) {
            String text = UTF8.decode(readCbor);
            if (format.equals("hex")) {
                readCbor = HexaDecimal.decode(text.replaceAll("#.*(\r|\n|$)", "")
                                                  .replaceAll("( |\n|\r)", ""));
            } else if (format.equals("b64u")) {
                readCbor = Base64URL.decode(text);
            } else {
                show();
            }
        }
        CBORObject decodedCborObject = CBORObject.decode(readCbor);
        byte[] decodedCbor = decodedCborObject.encode();
        System.out.println(decodedCborObject.toString());
        String readCborHex = HexaDecimal.encode(readCbor);
        String decodedCborHex = HexaDecimal.encode(decodedCbor);
        if (!readCborHex.equals(decodedCborHex)) {
            System.out.println("Failed to encode \n" + readCborHex + "\n" + decodedCborHex);
        }
    }

}

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

import org.webpki.cbor.CBORObject;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64URL;
import org.webpki.util.DebugFormatter;

/**
 * Decodes CBOR data.
 */
public class CBORPrinter {


    private CBORPrinter() {}  // No instantiation please

    ///////////////////////////////
    ////       DEBUGGING       ////
    ///////////////////////////////

    static void exitCommand() {
        System.out.println("\nUsage:\n\n  CBORPrinter hex|bin|b64u <infile>\n");
        System.exit(3);
    }

    /**
     * @param args Command line interface
     * @throws Exception If anything unexpected happens...
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 2) {
            exitCommand();
        }
        byte[] data = ArrayUtil.readFile(args[1]);
        String format = args[0];
        if (format.equals("hex")) {
            data = DebugFormatter.getByteArrayFromHex(new String(data, "utf-8"));
        } else if (format.equals("b64u")) {
            data = Base64URL.decode(new String(data, "utf-8"));
        } else if (!format.equals("bin")) {
            exitCommand();
        }
        CBORObject cbor = CBORObject.decode(data);
        System.out.println(cbor.toString());
        if (!ArrayUtil.compare(data, cbor.encode())) {
            System.out.println("Failed to encode");
        }
    }

}

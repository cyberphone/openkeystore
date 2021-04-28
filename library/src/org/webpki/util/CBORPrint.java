/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.util;

import org.webpki.cbor.CBORObject;

/**
 * Decodes CBOR data.
 */
public class CBORPrint {


    private CBORPrint() {}  // No instantiation please

    ///////////////////////////////
    ////       DEBUGGING       ////
    ///////////////////////////////

    static void exitCommand() {
        System.out.println("\nUsage:\n\n  org.webpki.util.CBORPrint <infile>\n");
        System.exit(3);
    }

    /**
     * @param args Command line interface
     * @throws Exception If anything unexpected happens...
     */
    public static void main(String[] args) throws Exception {
        if (args.length != 1) {
            exitCommand();
        }
        System.out.println(CBORObject.decode(ArrayUtil.readFile(args[0])).toString());
    }

}

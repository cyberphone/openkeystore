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

import java.io.IOException;

import org.webpki.util.ArrayUtil;
import org.webpki.util.HexaDecimal;

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

    public static void main(String[] args) throws IOException {
        if (args.length == 3 && args[0].equals("tobin")) {
            ArrayUtil.writeFile(args[2], HexaDecimal.decode(new String(ArrayUtil.readFile(args[1]), "UTF-8")));
            System.exit(0);
        }
        if (args.length != 2 || !(args[0].equals("hex") || args[0].equals("dump"))) {
            System.out.println("Usage: Hex hex|dump bininputfile \n" +
                               "           tobin inputfileinhex outputfilebin\n");
            System.exit(0);
        }
        byte[] data = ArrayUtil.readFile(args[1]);
        System.out.print(args[0].equals("dump") ? HexaDecimal.getHexDebugData(data) : HexaDecimal.encode(data));
    }

}

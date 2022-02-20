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
package org.webpki.cbor;

import java.io.IOException;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR text strings.
 */
public class CBORTextString extends CBORObject {

    String textString;

    /**
     * Creates a CBOR <code>text string</code>.
     */
    public CBORTextString(String textString) {
        this.textString = textString;
        nullCheck(textString);
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.TEXT_STRING;
    }

    @Override
    byte[] internalEncode() throws IOException {
        byte[] utf8 = textString.getBytes("utf-8");
        return ArrayUtil.add(encodeTagAndN(MT_TEXT_STRING, utf8.length), utf8);
    }

    // JavaScript/JSON compatible escape character support
    static final char[] SPECIAL_CHARACTERS = {
    //   0    1    2    3    4    5    6    7    8    9    A    B    C    D    E    F
         1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 , 'b', 't', 'n',  1 , 'f', 'r',  1 ,  1 ,
         1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,  1 ,
         0 ,  0 , '"',  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 , '\\'};
    
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append('"');
        for (char c : textString.toCharArray()) {
            if (c <= '\\') {
                char convertedCharacter;
                if ((convertedCharacter = SPECIAL_CHARACTERS[c]) != 0) {
                    cborPrinter.append('\\');
                    if (convertedCharacter == 1) {
                        cborPrinter.append(String.format("u%04x", (int)c));
                        continue;
                    }
                    c = convertedCharacter;
                }
            }
            cborPrinter.append(c);
        }
        cborPrinter.append('"');
    }
}

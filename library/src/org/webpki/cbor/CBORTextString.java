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
     * Create a CBOR <code>text string</code> object.
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
        return ArrayUtil.add(getEncodedCore(MT_TEXT_STRING, utf8.length), utf8);
    }

    // JavaScript/JSON compatible escape character support
    static final char[] SPECIAL_CHARACTERS = {
    //  00   01   02   03   04   05   06   07   08   09   0A   0B   0C   0D   0E   0F
        01 , 01 , 01 , 01 , 01 , 01 , 01,  01 , 'b', 't', 'n', 01 , 'f', 'r', 01 , 01 ,
        01 , 01 , 01 , 01 , 01 , 01 , 01,  01 , 01 , 01 , 01 , 01 , 01 , 01 , 01 , 01 ,
         0 ,  0 , '"',  0 ,  0 ,  0 ,  0,   0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0,   0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0,   0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0 ,
         0 ,  0 ,  0 ,  0 ,  0 ,  0 ,  0,   0 ,  0 ,  0 ,  0 ,  0 , '\\'};
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        StringBuilder buffer = new StringBuilder("\"");
        for (char c : textString.toCharArray()) {
            if (c <= '\\') {
                char convertedCharacter;
                if ((convertedCharacter = SPECIAL_CHARACTERS[c]) != 0) {
                    if (convertedCharacter == 1) {
                        buffer.append(String.format("\\u%04x", (int)c));
                    } else {
                        buffer.append('\\').append(convertedCharacter);
                    }
                    continue;
                }
            }
            buffer.append(c);
        }
        prettyPrinter.appendText(buffer.append('"').toString());
    }
}

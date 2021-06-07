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

    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
        prettyPrinter.appendText("\"").appendText(textString).appendText("\"");
    }
}

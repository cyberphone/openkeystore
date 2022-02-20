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
import org.webpki.util.HexaDecimal;

/**
 * Class for holding CBOR byte strings.
 */
public class CBORByteString extends CBORObject {

    byte[] byteString;

    /**
     * Creates a CBOR <code>byte string</code>.
     * 
     * @param byteString The bytes constituting the string
     */
    public CBORByteString(byte[] byteString) {
        this.byteString = byteString;
        nullCheck(byteString);
   }
    
    @Override
    CBORTypes internalGetType() {
        return CBORTypes.BYTE_STRING;
    }

    @Override
    byte[] internalEncode() throws IOException {
        return ArrayUtil.add(encodeTagAndN(MT_BYTE_STRING, byteString.length), byteString);
    }

    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append("h'").append(HexaDecimal.encode(byteString)).append('\'');
    }
}

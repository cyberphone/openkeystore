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
package org.webpki.cbor;

import org.webpki.util.HexaDecimal;

/**
 * Class for holding CBOR <code>byte&nbsp;string</code> objects.
 */
public class CBORBytes extends CBORObject {

    byte[] byteString;

    /**
     * Creates a CBOR <code>byte string</code>.
     * 
     * @param byteString The bytes constituting the string
     */
    public CBORBytes(byte[] byteString) {
        super(CBORTypes.BYTES);
        this.byteString = byteString;
        nullCheck(byteString);
    }

    @Override
    byte[] internalEncode() {
        return addByteArrays(encodeTagAndN(MT_BYTES, byteString.length), byteString);
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append("h'").append(HexaDecimal.encode(byteString)).append('\'');
    }
}

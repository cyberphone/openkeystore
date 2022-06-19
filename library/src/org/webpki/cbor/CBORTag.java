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

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR tagged objects.
 * 
 * Tagged objects are based on CBOR major type 6.
 * <p>
 * Note that the <code>big&nbsp;integer</code> type is dealt with
 * as a specific primitive, in spite of being a tagged object.
 * </p>
 */
public class CBORTag extends CBORObject {

    /**
     * CBOR representation.
     */
    long tagNumber;
    CBORObject object;
    
    /**
     * Creates a CBOR tagged object.
     * 
     * @param tagNumber Tag number
     * @param object Object
     */
    public CBORTag(long tagNumber, CBORObject object) {
        this.tagNumber = tagNumber;
        this.object = object;
        nullCheck(object);
    }

    /**
     * Returns tagged object.
     * @return CBOR object
     */
    public CBORObject getObject() {
        return object;
    }

    /**
     * Returns tag number.
     * @return Tag number
     */
    public long getTagNumber() {
        return tagNumber;
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.TAG;
    }
    
    @Override
    byte[] internalEncode() {
        return ArrayUtil.add(encodeTagAndN(MT_TAG, tagNumber), object.internalEncode());

    }
    
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
         cborPrinter.append(Long.toUnsignedString(tagNumber)).append('(');
         object.internalToString(cborPrinter);
         cborPrinter.append(')');
    }
}

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
 * Class for holding CBOR tagged objects.
 * 
 * Tagged objects are based on CBOR major type 6.
 * <p>
 * Note that the <code>big number</code> type is dealt with
 * as a specific primitive, in spite of being a tagged object.
 * </p>
 */
public class CBORTaggedObject extends CBORObject {

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
    public CBORTaggedObject(long tagNumber, CBORObject object) {
        this.tagNumber = tagNumber;
        this.object = object;
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.TAGGED_OBJECT;
    }
    
    @Override
    byte[] internalEncode() throws IOException {
        return ArrayUtil.add(getEncodedCore(MT_TAG_EXTENSION, tagNumber), object.internalEncode());

    }
    
    @Override
    void internalToString(CBORObject.PrettyPrinter prettyPrinter) {
         prettyPrinter.appendText(Long.toUnsignedString(tagNumber)).appendText("(");
         object.internalToString(prettyPrinter);
         prettyPrinter.appendText(")");
    }
}

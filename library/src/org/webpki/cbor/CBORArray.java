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

import java.util.ArrayList;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR arrays.
 */
public class CBORArray extends CBORObject {

    ArrayList<CBORObject> objectList = new ArrayList<>();

    /**
     * Creates an empty CBOR array <code>[]</code>.
     * 
     */
    public CBORArray() {}
    
    /**
     * Returns the size of the array.
     * 
     * @return The number of elements in the array
     */
    public int size() {
        return objectList.size();
    }
    
    /**
     * Retrieves object at a specific position.
     * 
     * @param index The position (0 - size-1)
     * @return CBOR object
     * @throws IOException
     */
    public CBORObject getObject(int index) throws IOException {
        return objectList.get(index);
    }
    
    /**
     * Appends object to the list.
     * 
     * @param cborObject
     * @return <code>this</code>
     */
    public CBORArray addObject(CBORObject cborObject) {
        objectList.add(cborObject);
        return this;
    }
    
    /**
     * Returns the entire array.
     * 
     * @return Array of CBOR objects
     */
    public CBORObject[] getObjects() {
        return objectList.toArray(new CBORObject[0]);
    }

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.ARRAY;
    }

    @Override
    byte[] internalEncode() throws IOException {
        byte[] encoded = encodeTagAndN(MT_ARRAY, objectList.size());
        for (CBORObject cborObject : getObjects()) {
            encoded = ArrayUtil.add(encoded, cborObject.internalEncode());
        }
        return encoded;
    }

    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.append('[');
        boolean notFirst = false;
        for (CBORObject cborObject : getObjects()) {
            if (notFirst) {
                cborPrinter.append(", ");
            }
            notFirst = true;
            cborObject.internalToString(cborPrinter);
        }
        cborPrinter.append(']');
    }
}

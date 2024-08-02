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

import java.util.ArrayList;

/**
 * Class for holding CBOR <code>array</code> objects.
 */
public class CBORArray extends CBORObject {

    ArrayList<CBORObject> objects = new ArrayList<>();

    /**
     * Creates an empty CBOR array <code>[]</code>.
     * 
     */
    public CBORArray() {
        super(CBORTypes.ARRAY);
    }
    
    /**
     * Get size of the CBOR <code>array</code>.
     * 
     * @return The number of objects in the array
     */
    public int size() {
        return objects.size();
    }
    
    /**
     * Get object at a specific position in the CBOR <code>array</code>.
     * 
     * @param index The position (0..size()-1)
     * @return CBOR object
     * @throws IndexOutOfBoundsException If the index is out of range.
     */
    public CBORObject get(int index) {
        return objects.get(index);
    }
    
    /**
     * Add object to the CBOR <code>array</code>.
     * 
     * @param cborObject Object to be appended to the array.
     * @return <code>this</code>
     */
    public CBORArray add(CBORObject cborObject) {
        nullCheck(cborObject);
        objects.add(cborObject);
        return this;
    }
    
    /**
     * Create shallow copy of the CBOR <code>array</code>.
     * 
     * @return Array of CBOR objects
     */
    public CBORObject[] toArray() {
        return objects.toArray(new CBORObject[0]);
    }

    @Override
    byte[] internalEncode() {
        byte[] encoded = encodeTagAndN(MT_ARRAY, objects.size());
        for (CBORObject cborObject : toArray()) {
            encoded = addByteArrays(encoded, cborObject.encode());
        }
        return encoded;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append('[');
        boolean notFirst = false;
        for (CBORObject cborObject : toArray()) {
            if (notFirst) {
                cborPrinter.append(',');
                cborPrinter.space();
            }
            notFirst = true;
            cborObject.internalToString(cborPrinter);
        }
        cborPrinter.append(']');
    }
}

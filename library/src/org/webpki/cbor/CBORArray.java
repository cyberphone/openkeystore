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

import java.util.ArrayList;

/**
 * Class for holding CBOR <code>array</code> objects.
 */
public class CBORArray extends CBORObject {

    ArrayList<CBORObject> elements = new ArrayList<>();

    /**
     * Creates an empty CBOR array <code>[]</code>.
     * 
     */
    public CBORArray() {
        super(CBORTypes.ARRAY);
    }
    
    /**
     * Returns the size of the array.
     * 
     * @return The number of objects in the array
     */
    public int size() {
        return elements.size();
    }
    
    /**
     * Retrieves object at a specific position.
     * 
     * @param index The position (0 - size-1)
     * @return CBOR object
     */
    public CBORObject get(int index) {
        return elements.get(index);
    }
    
    /**
     * Appends object to the list.
     * 
     * @param element Object to be appended
     * @return <code>this</code>
     */
    public CBORArray add(CBORObject element) {
        nullCheck(element);
        elements.add(element);
        return this;
    }
    
    /**
     * Returns the entire array.
     * 
     * @return Array of CBOR objects
     */
    public CBORObject[] toArray() {
        return elements.toArray(new CBORObject[0]);
    }

    @Override
    byte[] internalEncode() {
        byte[] encoded = encodeTagAndN(MT_ARRAY, elements.size());
        for (CBORObject cborObject : toArray()) {
            encoded = addByteArrays(encoded, cborObject.encode());
        }
        return encoded;
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append('[');
        boolean notFirst = false;
        for (CBORObject object : toArray()) {
            if (notFirst) {
                cborPrinter.append(',');
                cborPrinter.space();
            }
            notFirst = true;
            object.internalToString(cborPrinter);
        }
        cborPrinter.append(']');
    }
}

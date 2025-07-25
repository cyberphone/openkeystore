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

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>[]</code> (array) objects.
 */
public class CBORArray extends CBORObject {

    ArrayList<CBORObject> objects = new ArrayList<>();

    /**
     * Creates an empty CBOR <code>[]</code> (array).
     * 
     */
    public CBORArray() {}
    
    /**
     * Get size of the CBOR array.
     * 
     * @return The number of objects in the array
     */
    public int size() {
        return objects.size();
    }
    
    /**
     * Get object at a specific position in the CBOR array.
     * 
     * @param index The position (0..size()-1)
     * @return CBOR object
     * @throws IndexOutOfBoundsException If the index is out of range.
     */
    public CBORObject get(int index) {
        return objects.get(index);
    }
    
    /**
     * Add object to the CBOR array.
     * <p>
     * Also see {@link CBORArray#update(int, CBORObject)}
     * </p>
     * 
     * @param object Object to be appended to the array.
     * @return <code>this</code>
     */
    public CBORArray add(CBORObject object) {
        immutableTest();
        objects.add(checkObject(object));
        return this;
    }
    
    /**
     * Update object at a specific position in the CBOR array.
     * 
     * @param index The position (<code>0..size()-1</code>)
     * @param object Object to set
     * @return Previous <code>object</code>
     * @throws IndexOutOfBoundsException If the index is out of range.
     */
    public CBORObject update(int index, CBORObject object) {
        immutableTest();
        return objects.set(index, checkObject(object));
    }

    byte[] encodeBody(byte[] header) {
        for (CBORObject cborObject : objects) {
            header = addByteArrays(header, cborObject.internalEncode());
        }
        return header;
    }

    /**
     * Encode CBOR sequence.
     * <p>
     * Return the objects in the array as a CBOR sequence using
     * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>.
     * </p>
     * 
     * @return CBOR sequence
     */
    public byte[] encodeAsSequence() {
        return encodeBody(new byte[0]);
    }

    /**
     * Create shallow copy of the CBOR array.
     * 
     * @return Array of CBOR objects
     */
    @SuppressWarnings("unchecked")
    public ArrayList<CBORObject> toArray() {
        return (ArrayList<CBORObject>) objects.clone();
    }

    @Override
    byte[] internalEncode() {
        return encodeBody(encodeTagAndN(MT_ARRAY, objects.size()));
    }

    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.append('[');
        boolean notFirst = false;
        for (CBORObject cborObject : objects) {
            if (notFirst) {
                cborPrinter.append(',').space();
            }
            notFirst = true;
            cborObject.internalToString(cborPrinter);
        }
        cborPrinter.append(']');
    }
}

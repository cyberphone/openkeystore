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
 * Class for creating CBOR sequences.
 */
public class CBORSequenceBuilder {

    ArrayList<CBORObject> sequence = new ArrayList<>();

    /**
     * Creates a CBOR sequence builder.
     * <p>
     * Also see {@link CBORDecoder#CBORDecoder(java.io.InputStream, boolean, boolean, boolean, Integer)}.
     * </p>
     * 
     */
    public CBORSequenceBuilder() {
        
    }
    
    /**
     * Add object to CBOR sequence.
     * 
     * @param object Object to be appended
     * @return <code>this</code>
     */
    public CBORSequenceBuilder add(CBORObject object) {
        CBORObject.nullCheck(object);
        sequence.add(object);
        return this;
    }
    
    /**
     * Get completed CBOR sequence.
     * 
     * @return CBOR sequence
     */
    public byte[] encode() {
        byte[] cborBinary = new byte[0];
        for (CBORObject cborObject : sequence) {
            cborBinary = CBORObject.addByteArrays(cborBinary, cborObject.encode());
        }
        return cborBinary;
    }

    /**
     * Render CBOR sequence in diagnostic notation.
     * @return String
     */
    @Override
    public String toString() {
        StringBuilder s = new StringBuilder();
        boolean notFirst = false;
        for (CBORObject object : sequence) {
            if (notFirst) {
                s.append(",\n");
            }
            notFirst = true;
            s.append(object.toString());
        }
        return s.toString();
    }
}

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

import org.webpki.util.ArrayUtil;

/**
 * Class for creating CBOR sequences.
 */
public class CBORSequenceBuilder {

    ArrayList<CBORObject> sequence = new ArrayList<>();

    /**
     * Creates a CBOR sequence builder.
     * <p>
     * See {@link CBORObject#decode(InputStream, boolean, boolean, boolean, Integer)}.
     * </p>
     * 
     */
    public CBORSequenceBuilder() {
        
    }
    
    /**
     * Appends object to the sequence.
     * 
     * @param cborObject
     * @return <code>this</code>
     */
    public CBORSequenceBuilder addObject(CBORObject cborObject) {
        CBORObject.nullCheck(cborObject);
        sequence.add(cborObject);
        return this;
    }
    
    /**
     * Returns the completed sequence.
     * 
     * @return CBOR sequence
     */
    public byte[] encode() {
        byte[] cborBinary = new byte[0];
        for (CBORObject cborObject : sequence) {
            cborBinary = ArrayUtil.add(cborBinary, cborObject.encode());
        }
        return cborBinary;
    }
}
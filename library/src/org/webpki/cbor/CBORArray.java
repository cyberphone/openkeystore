/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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

import java.math.BigInteger;

import java.util.ArrayList;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR arrays.
 */
public class CBORArray extends CBORObject {

    private static final long serialVersionUID = 1L;

    ArrayList<CBORObject> elements = new ArrayList<>();

    public CBORArray() {
    }
    
    public CBORObject getObject(int index) throws IOException {
        return elements.get(index);
    }
    
    public CBORArray addObject(CBORObject cborObject) {
        elements.add(cborObject);
        return this;
    }
    
    public int getInt32(int index) throws IOException {
        return getObject(index).getInt32();
    }

    public long getInt64(int index) throws IOException {
        return getObject(index).getInt64();
    }

    public BigInteger getBigInteger(int index) throws IOException {
        return getObject(index).getBigInteger();
    }
 
    @Override
    public CBORTypes getType() {
        return CBORTypes.ARRAY;
    }

    @Override
    public byte[] encodeObject() throws IOException {
        byte[] encoded = getEncodedCodedValue(MT_ARRAY, elements.size(), false, false);
        for (CBORObject element : elements.toArray(new CBORObject[0])) {
            encoded = ArrayUtil.add(encoded, element.encodeObject());
        }
        return encoded;
    }

    @Override
    void internalToString(CBORObject initiator) {
        StringBuilder result = initiator.result;
  //      initiator.indent();
        result.append("[\n");
        initiator.indentationLevel++;
        boolean notFirst = false;
        for (CBORObject element : elements.toArray(new CBORObject[0])) {
            if (notFirst) {
                result.insert(result.length() - 1, ',');
            }
            notFirst = true;
            initiator.indent();
            element.internalToString(initiator);
            result.append('\n');
        }
        initiator.indentationLevel--;
        initiator.indent();
        result.append(']');
    }
}

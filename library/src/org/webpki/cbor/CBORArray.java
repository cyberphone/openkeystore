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

    ArrayList<CBORObject> elements = new ArrayList<>();

    public CBORArray() {}
    
    public CBORObject getElement(int index) throws IOException {
        return elements.get(index);
    }
    
    public CBORArray addElement(CBORObject cborObject) {
        elements.add(cborObject);
        return this;
    }
    
    public CBORObject[] getElements() {
        return elements.toArray(new CBORObject[0]);
    }
 
    @Override
    public CBORTypes getType() {
        return CBORTypes.ARRAY;
    }

    @Override
    public byte[] encode() throws IOException {
        byte[] encoded = getEncodedCore(MT_ARRAY, elements.size());
        for (CBORObject element : getElements()) {
            encoded = ArrayUtil.add(encoded, element.encode());
        }
        return encoded;
    }

    @Override
    void internalToString(CBORObject initiator) {
        StringBuilder prettyPrintCopy = initiator.prettyPrint;
        prettyPrintCopy.append("[\n");
        initiator.indentationLevel++;
        boolean notFirst = false;
        for (CBORObject element : getElements()) {
            if (notFirst) {
                prettyPrintCopy.insert(prettyPrintCopy.length() - 1, ',');
            }
            notFirst = true;
            initiator.indent();
            element.internalToString(initiator);
            prettyPrintCopy.append('\n');
        }
        initiator.indentationLevel--;
        initiator.indent();
        prettyPrintCopy.append(']');
    }
}

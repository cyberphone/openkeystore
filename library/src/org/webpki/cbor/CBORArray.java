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

import java.util.ArrayList;

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
        cborObject.parent = this;
        elements.add(cborObject);
        return this;
    }
    
    public int getInt32(int index) throws IOException {
        return getObject(index).getInt32();
    }

    public long getInt64(int index) throws IOException {
        return getObject(index).getInt64();
    }

    @Override
    public CBORTypes getType() {
        return CBORTypes.ARRAY;
    }

    @Override
    public byte[] writeObject() throws IOException {
        return new byte[] {6,7};
    }

    @Override
    StringBuilder internalToString(StringBuilder result) {
        StringBuilder indent = parentDepthIndent();
        result.append("[\n");
        boolean notFirst = false;
        for (CBORObject element : elements.toArray(new CBORObject[0])) {
            if (notFirst) {
                result.insert(result.length() - 1, ',');
            }
            notFirst = true;
            result.append(indent)
                  .append(INDENT)
                  .append(element.toString());
        }
        return result.append(indent).append(']');
    }
}

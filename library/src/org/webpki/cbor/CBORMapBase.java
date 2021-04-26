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

import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

/**
 * Base class for holding CBOR maps.
 */
abstract class CBORMapBase extends CBORObject {

    private static final long serialVersionUID = 1L;

    class CBORKeyComparer implements Comparator<CBORObject> {

        @Override
        public int compare(CBORObject o1, CBORObject o2) {
            return o1.toString().compareTo(o2.toString());
        }
    }

    Map<CBORObject, CBORObject> keys = new TreeMap<>(new CBORKeyComparer());

    CBORMapBase() {
    }

    void setObject(CBORObject key, CBORObject value) throws IOException {
        if (keys.put(key, value) != null) {
            throw new IOException("Duplicate key: " + key.toString());
        }
    }

    CBORObject getObject(CBORObject key) throws IOException {
        CBORObject cborObject = keys.get(key);
        if (cborObject == null) {
            throw new IOException("No such key: " + key.toString());
        }
        return cborObject;
    }

    static String keyText(CBORObject key) {
        String keyText = key.toString();
        return keyText.substring(0, keyText.length() - 1);
    }

    @Override
    public CBORTypes getType() {
        return CBORTypes.MAP;
    }
 
    @Override
    public byte[] writeObject() throws IOException {
        // TODO Auto-generated method stub
        return null;
    }
    
    @Override
    StringBuilder internalToString() {
        StringBuilder indent = parentDepthIndent();
        StringBuilder result = new StringBuilder("{\n");
        boolean notFirst = false;
        for (CBORObject key : keys.keySet()) {
            CBORObject member = keys.get(key);
            if (notFirst) {
                result.insert(result.length() - 1, ',');
            }
            notFirst = true;
            result.append(indent)
                  .append(INDENT)
                  .append(keyText(key))
                  .append(": ")
                  .append(member.toString());
        }
        return result.append(indent).append('}');
    }
}

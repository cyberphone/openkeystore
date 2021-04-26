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

import java.util.TreeMap;

/**
 * Class for holding CBOR string maps.
 */
public class CBORStringMap extends CBORObject {

    private static final long serialVersionUID = 1L;

    TreeMap<String, CBORObject> keys = new TreeMap<>();

    CBORStringMap() {
    }

    public CBORStringMap setObject(String key, CBORObject value) throws IOException {
        if (keys.put(key, value) != null) {
            throw new IOException("Duplicate key: " + key);
        }
        return this;
    }

    public CBORObject getObject(String key) throws IOException {
        CBORObject cborObject = keys.get(key);
        if (cborObject == null) {
            throw new IOException("No such key: " + key);
        }
        return cborObject;
    }

    public int getInt32(String key) throws IOException {
        return getObject(key).getInt32();
    }

    public long getInt64(String key) throws IOException {
        return getObject(key).getInt64();
    }

    public byte[] getByteArray(String key) throws IOException {
        return getObject(key).getByteArray();
    }

    public CBORArray getCBORArray(String key) throws IOException {
        return getObject(key).getCBORArray();
    }

    public CBORStringMap getCBORMap(String key) throws IOException {
        return getObject(key).getCBORStringMap();
    }

    @Override
    public CBORTypes getType() {
        return CBORTypes.STRING_MAP;
    }

    @Override
    public byte[] writeObject() throws IOException {
        // TODO Auto-generated method stub
        return new byte[] {6,7};
    }

    @Override
    StringBuilder internalToString() {
        StringBuilder indent = parentDepthIndent();
        StringBuilder result = new StringBuilder("{\n");
        boolean notFirst = false;
        for (String key : keys.keySet()) {
            CBORObject member = keys.get(key);
            if (notFirst) {
                result.insert(result.length() - 1, ',');
            }
            notFirst = true;
            result.append(indent)
                  .append(INDENT)
                  .append('"')
                  .append(key)
                  .append("\": ")
                  .append(member.toString());
        }
        return result.append(indent).append('}');
    }
}

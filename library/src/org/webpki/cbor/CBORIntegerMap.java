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

/**
 * Class for holding CBOR integer maps.
 */
public class CBORIntegerMap extends CBORMapBase {

    private static final long serialVersionUID = 1L;

    CBORIntegerMap() {
    }

    CBORIntegerMap setObject(int key, CBORObject value) throws IOException {
        setObject(new CBORInteger(key), value);
        return this;
    }

    CBORObject getObject(int key) throws IOException {
        return getObject(new CBORInteger(key));
    }

    public int getInt32(int key) throws IOException {
        return getObject(key).getInt32();
    }

    public long getInt64(int key) throws IOException {
        return getObject(key).getInt64();
    }

    public byte[] getByteArray(int key) throws IOException {
        return getObject(key).getByteArray();
    }

    public CBORArray getArray(int key) throws IOException {
        return getObject(key).getArray();
    }

    public CBORIntegerMap getIntegerMap(int key) throws IOException {
        return getObject(key).getIntegerMap();
    }

    public CBORStringMap getStringMap(int key) throws IOException {
        return getObject(key).getStringMap();
    }
    
}

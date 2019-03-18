/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.json;

import java.io.IOException;
import java.util.LinkedHashMap;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/*
 * Holder if symmetric keys
 */
public class SymmetricKeys {

    private LinkedHashMap<Integer,byte[]> keys = new LinkedHashMap<Integer,byte[]>();
    
    private String keyBase;
  
    public SymmetricKeys(String keyBase) throws IOException {
        this.keyBase = keyBase;
        init(128);
        init(256);
        init(384);
        init(512);
    }

    private void init(int i) throws IOException {
        keys.put(i,        
                 DebugFormatter.getByteArrayFromHex(new String(ArrayUtil.readFile(keyBase + getName(i) + ".hex"), "utf-8")));
    }

    public String getName(int i) throws IOException {
        return "a" + i + "bitkey";
    }

    public byte[] getValue(int i) throws IOException {
        byte[] key = keys.get(i);
        if (key == null){
            throw new IOException("No such key: " + i);
        }
        if (key.length * 8 != i) {
            throw new IOException("Bad sym key:" + key.length);
        }
        return key;
    }
}

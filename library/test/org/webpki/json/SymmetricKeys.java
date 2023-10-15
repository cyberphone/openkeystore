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
package org.webpki.json;

import java.util.LinkedHashMap;

import org.webpki.util.IO;
import org.webpki.util.UTF8;
import org.webpki.util.HexaDecimal;

import org.webpki.crypto.CryptoException;

/*
 * Holder of symmetric keys
 */
public final class SymmetricKeys {

    private LinkedHashMap<Integer,byte[]> keys = new LinkedHashMap<>();
    
    private String keyBase;
  
    public SymmetricKeys(String keyBase) {
        this.keyBase = keyBase;
        init(128);
        init(256);
        init(384);
        init(512);
    }

    private void init(int i) {
        keys.put(i,        
                 HexaDecimal.decode(UTF8.decode(IO.readFile(keyBase + getName(i) + ".hex"))));
    }

    public String getName(int i) {
        return "a" + i + "bitkey";
    }

    public byte[] getValue(int i) {
        byte[] key = keys.get(i);
        if (key == null){
            throw new CryptoException("No such key: " + i);
        }
        if (key.length * 8 != i) {
            throw new CryptoException("Bad sym key:" + key.length);
        }
        return key;
    }
}

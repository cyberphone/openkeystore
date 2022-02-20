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

import java.util.Comparator;
import java.util.Map;
import java.util.TreeMap;

import org.webpki.util.ArrayUtil;

/**
 * Class for holding CBOR maps.
 * <p>
 * In addition to supporting the generic {@link CBORObject} type for key identifiers,
 * there are convenience methods for 
 * retrieving (<code>getObject</code>), 
 * setting (<code>setObject</code>),
 * testing (<code>hasKey</code>), and
 * removing (<code>removeObject</code>)
 * objects using the Java <code>String</code> and <code>int</code> types for key identifiers.
 * The latter maps to the CBOR <code>text&nbsp;string</code> and <code>integer</code>
 * type respectively.
 * </p>
 */
public class CBORMap extends CBORObject {

    boolean parsingMode;
    CBORObject lastKey;

    private static Comparator<CBORObject> comparator = new Comparator<CBORObject>() {

        @Override
        public int compare(CBORObject o1, CBORObject o2) {
            try {
                byte[] key1 = o1.internalEncode();
                byte[] key2 = o2.internalEncode();
                int minIndex = Math.min(key1.length, key2.length);
                for (int i = 0; i < minIndex; i++) {
                    int diff = (key1[i] & 0xff) - (key2[i] & 0xff);
                    if (diff != 0) {
                        return diff;
                    }
                }
                return key1.length - key2.length;
            } catch (IOException e) {
                 throw new RuntimeException(e);
            }
        }
        
    };

    Map<CBORObject, CBORObject> keys = new TreeMap<>(comparator);
    
    /**
     * Creates an empty CBOR <code>map</code>.
     */
    public CBORMap() {
    }
    

    @Override
    CBORTypes internalGetType() {
        return CBORTypes.MAP;
    }
    
    /**
     * Returns the size of the map.
     * 
     * @return The number of entries (keys) in the map
     */
    public int size() {
        return keys.size();
    }

    /**
     * Checks map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(CBORObject key) {
        return keys.containsKey(key);
    }

    /**
     * Checks map for key presence.
     * <p>
     * See {@link #hasKey(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(int key) {
        return hasKey(new CBORInteger(key));
    }
    
    /**
     * Checks map for key presence.
     * <p>
     * See {@link #hasKey(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(String key) {
        return hasKey(new CBORTextString(key));
    }
    
    /**
     * Sets map object.
     * <p>
     * If <code>key</code> is already present, an exception is thrown.
     * </p>
     * 
     * @param key Key
     * @param value Object
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(CBORObject key, CBORObject value) throws IOException {
        if (keys.put(key, value) != null) {
            reportError("Duplicate key: " + key.toString());
        }
        if (parsingMode) {
            if (comparator.compare(lastKey, key) > 0) {
                reportError("Non-deterministic sort order for map key: " + key);
            }
        }
        lastKey = key;
        return this;
    }

    /**
     * Sets map object.
     * <p>
     * See {@link #setObject(CBORObject, CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @param value Object
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(int key, CBORObject value) throws IOException {
        setObject(new CBORInteger(key), value);
        return this;
    }

    /**
     * Sets map object.
     * <p>
     * See {@link #setObject(CBORObject, CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @param value Object
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setObject(String key, CBORObject value) throws IOException {
        setObject(new CBORTextString(key), value);
        return this;
    }
    
     /**
     * Retrieves map object.
     * <p>
     * If <code>key</code> is not present, an exception is thrown.
     * </p>
     * 
     * @param key Key
     * @return Object
     * @throws IOException
     */
    public CBORObject getObject(CBORObject key) throws IOException {
        CBORObject cborObject = keys.get(key);
        if (cborObject == null) {
            reportError("Missing key: " + key.toString());
        }
        return cborObject;
    }

    /**
     * Retrieves map object.
     * <p>
     * See {@link #getObject(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return Object
     * @throws IOException
     */
    public CBORObject getObject(int key) throws IOException {
        return getObject(new CBORInteger(key));
    }
    
    /**
     * Retrieves map object.
     * <p>
     * See {@link #getObject(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return Object
     * @throws IOException
     */
    public CBORObject getObject(String key) throws IOException {
        return getObject(new CBORTextString(key));
    }
    
    /**
     * Removes mapped object.
     * <p>
     * If <code>key</code> is not present, an exception is thrown.
     * </p>
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(CBORObject key) throws IOException {
        if (!keys.containsKey(key)) {
            reportError("No such key: " + key.toString());
        }
        keys.remove(key);
        return this;
    }

    /**
     * Removes mapped object.
     * <p>
     * See {@link #removeObject(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(int key) throws IOException {
        removeObject(new CBORInteger(key));
        return this;
    }

    /**
     * Removes mapped object.
     * <p>
     * See {@link #removeObject(CBORObject)} for details.
     * </p>
     * 
     * @param key Key
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap removeObject(String key) throws IOException {
        removeObject(new CBORTextString(key));
        return this;
    }

    /**
     * Enumerates all keys in a map.
     * 
     * @return Array of keys
     */
    public CBORObject[] getKeys() {
        return keys.keySet().toArray(new CBORObject[0]);
    }

    /**
     * Reads a <code>byte string</code> value, then deletes key.
     * <p>
     * If <code>key</code> is not present or the
     * mapped data is not a CBOR <code>byte&nbsp;string</code>,
     * an exception is thrown.
     * </p>
     * <p>
     * This method is provided for supporting the validation phase
     * of enveloped cryptographic constructs like CSF and CEF.
     * </p>
     * 
     * @param key Integer key
     * @return byte string
     * @throws IOException
     */
    public byte[] readByteStringAndRemoveKey(CBORInteger key) throws IOException {
        byte[] data = getObject(key).getByteString();
        removeObject(key);
        return data;
    }

    @Override
    byte[] internalEncode() throws IOException {
        byte[] encoded = encodeTagAndN(MT_MAP, keys.size());
        for (CBORObject key : keys.keySet()) {
            encoded = ArrayUtil.add(encoded,
                                    ArrayUtil.add(key.internalEncode(), 
                                                  keys.get(key).internalEncode()));
        }
        return encoded;
    }
        
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.beginMap();
        boolean notFirst = false;
        for (CBORObject key : keys.keySet()) {
            CBORObject value = keys.get(key);
            if (notFirst) {
                cborPrinter.append(',');
            }
            notFirst = true;
            cborPrinter.newlineAndIndent();
            key.internalToString(cborPrinter);
            cborPrinter.append(": ");
            value.internalToString(cborPrinter);
        }
        cborPrinter.endMap(notFirst);
    }
}

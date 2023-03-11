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

import org.webpki.util.ArrayUtil;

/**
 * Class for holding <code>CBOR</code> map.
 */
public class CBORMap extends CBORObject {

    boolean deterministicMode;
    boolean constrainedKeys;
    Entry root;
    private Entry lastEntry;

    // Similar to the Java Map.Entry but optimized for CBOR. 
    static class Entry {
        CBORObject key;
        CBORObject value;
        byte[] encodedKey;
        Entry next;
        
        Entry(CBORObject key, CBORObject value) {
            this.key = key;
            this.value = value;
            this.encodedKey = key.encode();
        }
        
        int compare(byte[] testKey) {
            int minIndex = Math.min(encodedKey.length, testKey.length);
            for (int i = 0; i < minIndex; i++) {
                int diff = (encodedKey[i] & 0xff) - (testKey[i] & 0xff);
                if (diff != 0) {
                    return diff;
                }
            }
            return encodedKey.length - testKey.length;
        }
    }

    /**
     * Creates an empty CBOR <code>map</code>.
     */
    public CBORMap() {
    }
    

    @Override
    public CBORTypes getType() {
        return CBORTypes.MAP;
    }
    
    /**
     * Returns the size of the map.
     * 
     * @return The number of entries (keys) in the map
     */
    public int size() {
        int i = 0;
        for (Entry entry = root; entry != null; entry = entry.next) {
            i++;
        }
        return i;
    }

    /**
     * Checks map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean hasKey(CBORObject key) {
        byte[] testKey = key.encode();
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (entry.compare(testKey) == 0) {
                return true;
            }
        }
        return false;
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
        if (constrainedKeys && !key.getType().permittedConstrainedKey) {
            reportError(STDERR_CONSTRAINED_KEYS + key);
        }
        Entry newEntry = new Entry(key, value);
        if (root == null) {
            root = newEntry;
        } else {
            // Note: the keys are always sorted, making the verification process simple.
            // This is also the reason why the Java "TreeMap" was not used. 
            if (constrainedKeys && lastEntry.key.getType() != key.getType()) {
                reportError(STDERR_CONSTRAINED_KEYS + key);
            }
            if (deterministicMode) {
                // Normal case for parsing.
                int diff = lastEntry.compare(newEntry.encodedKey);
                if (diff >= 0) {
                    reportError((diff == 0 ? 
                      STDERR_DUPLICATE_KEY : STDERR_NON_DET_SORT_ORDER) + key);
                }
                lastEntry.next = newEntry;
             } else {
                // Programmatically created key or the result of unconstrained parsing.
                // Then we need to test and sort (always produce deterministic CBOR).
                Entry  precedingEntry = null;
                int diff = 0;
                for (Entry entry = root; entry != null; entry = entry.next) {
                    diff = entry.compare(newEntry.encodedKey);
                    if (diff == 0) {
                        reportError(STDERR_DUPLICATE_KEY + key);                      
                    } else if (diff > 0) {
                        // New key is less than a current entry.
                        if (precedingEntry == null) {
                            // Less than root, means the root must be redefined.
                            newEntry.next = root;
                            root = newEntry;
                        } else {
                            // Somewhere above root. Insert after preceding entry.
                            newEntry.next = entry;
                            precedingEntry.next = newEntry;
                        }
                        break;
                    }
                    precedingEntry = entry;
                }
                if (diff < 0) {
                    precedingEntry.next = newEntry;
                }
            }
        }
        lastEntry = newEntry;
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
        byte[] testKey = key.encode();
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (entry.compare(testKey) == 0) {
                return entry.value;
            }
        }
        reportError(STDERR_MISSING_KEY + key);
        return null;
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
        byte[] testKey = key.encode();
        Entry precedingEntry = null;
        for (Entry entry = root; entry != null; entry = entry.next) {
            int diff = entry.compare(testKey);
            if (diff == 0) {
                if (precedingEntry == null) {
                    // Remove root key.  It may be alone.
                    root = entry.next;
                } else {
                    // Remove key above root.  It may be the top most.
                    precedingEntry.next = entry.next;
                }
                return this;
            }
            precedingEntry = entry;
        }
        reportError(STDERR_MISSING_KEY + key);
        return null;
    }

    /**
     * Enumerates all keys in a map.
     * 
     * @return Array of keys
     */
    public CBORObject[] getKeys() {
        CBORObject[] keys = new CBORObject[size()];
        int i = 0;
        for (Entry entry = root; entry != null; entry = entry.next) {
            keys[i++] = entry.key;
        }
        return keys;
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
     * @param key Key
     * @return byte string
     * @throws IOException
     */
    public byte[] readByteStringAndRemoveKey(CBORObject key) throws IOException {
        byte[] data = getObject(key).getByteString();
        removeObject(key);
        return data;
    }

    /**
     * Sets a <code>byte string</code> value.
     * <p>
     * If <code>key</code> is not present an exception is thrown.
     * </p>
     * <p>
     * This convenience method is provided for supporting
     * cryptographic constructs like CSF and CEF.
     * </p>
     * 
     * @param key Key
     * @param byteString Byte string
     * @return <code>this</code>
     * @throws IOException
     */
    public CBORMap setByteString(CBORObject key, byte[] byteString) throws IOException {
        return setObject(key, new CBORByteString(byteString));
    }
    
    @Override
    public byte[] encode() {
        byte[] encoded = encodeTagAndN(MT_MAP, size());
        for (Entry entry = root; entry != null; entry = entry.next) {
            encoded = ArrayUtil.add(encoded,
                                    ArrayUtil.add(entry.encodedKey, entry.value.encode()));
        }
        return encoded;
    }
        
    @Override
    void internalToString(CBORObject.DiagnosticNotation cborPrinter) {
        cborPrinter.beginMap();
        boolean notFirst = false;
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (notFirst) {
                cborPrinter.append(',');
            }
            notFirst = true;
            cborPrinter.newlineAndIndent();
            entry.key.internalToString(cborPrinter);
            cborPrinter.append(": ");
            entry.value.internalToString(cborPrinter);
        }
        cborPrinter.endMap(notFirst);
    }
    
    static final String STDERR_CONSTRAINED_KEYS = 
            "Constrained mode type error for map key: ";
    
    static final String STDERR_NON_DET_SORT_ORDER =
            "Non-deterministic sort order for map key: ";
    
    static final String STDERR_DUPLICATE_KEY = 
            "Duplicate key: ";

    static final String STDERR_MISSING_KEY = 
            "Missing key: ";
}

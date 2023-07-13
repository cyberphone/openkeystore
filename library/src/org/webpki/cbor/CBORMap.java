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

import java.util.Arrays;

/**
 * Class for holding CBOR <code>map</code> objects.
 */
public class CBORMap extends CBORObject {

    boolean deterministicMode;
    Entry root;
    private Entry lastEntry;
    private int numberOfEntries;

    // Similar to the Java Map.Entry but optimized for CBOR. 
    static class Entry {
        CBORObject key;
        CBORObject value;
        byte[] encodedKey;
        Entry next;
        
        Entry(CBORObject key, CBORObject object) {
            this.key = key;
            this.value = object;
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
        super(CBORTypes.MAP);
    }

    private CBORObject getKey(CBORObject key) {
        nullCheck(key);
        return key;
    }
    
    /**
     * Returns the size of the map.
     * 
     * @return The number of entries (keys) in the map
     */
    public int size() {
        return numberOfEntries;
    }

    /**
     * Sets mapped object.
     * <p>
     * If <code>key</code> is already present, a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key
     * @param value Value
     * @return <code>this</code>
     */
    public CBORMap set(CBORObject key, CBORObject value) {
        key = getKey(key);
        nullCheck(value);
        Entry newEntry = new Entry(key, value);
        if (root == null) {
            root = newEntry;
        } else {
            // Keys are always sorted, making the verification process simple.
            if (deterministicMode) {
                // Normal case for parsing.
                int diff = lastEntry.compare(newEntry.encodedKey);
                if (diff >= 0) {
                    cborError((diff == 0 ? 
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
                        cborError(STDERR_DUPLICATE_KEY + key);                      
                    }
                    if (diff > 0) {
                        // New key is (lexicographically) smaller than current entry.
                        if (precedingEntry == null) {
                            // New key is smaller than root. New key becomes root.
                            newEntry.next = root;
                            root = newEntry;
                        } else {
                            // New key is smaller than an entry above root.
                            // Insert before current entry.
                            newEntry.next = entry;
                            precedingEntry.next = newEntry;
                        }
                        // Done, break out of the loop.
                        break;
                    }
                    // No luck in this round, continue searching.
                    precedingEntry = entry;
                }
                // Biggest key so far, insert at the end.
                if (diff < 0) {
                    precedingEntry.next = newEntry;
                }
            }
        }
        lastEntry = newEntry;
        numberOfEntries++;
        return this;
    }

    private Entry lookup(CBORObject key, boolean mustExist) {
        byte[] encodedKey = getKey(key).encode();
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (Arrays.equals(entry.encodedKey, encodedKey)) {
                return entry;
            }
        }
        if (mustExist) {
            cborError(STDERR_MISSING_KEY + key);
        }
        return null;
    }

     /**
     * Returns mapped object.
     * <p>
     * If <code>key</code> is not present, a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key
     * @return <code>CBORObject</code>
     */
    public CBORObject get(CBORObject key) {
        return lookup(key, true).value;
    }

    /**
     * Returns mapped object conditionally.
     * <p>
     * If <code>key</code> is not present, <code>defaultValue</code> is returned.
     * <code>defaultValue</code> may be <code>null</code>.
     * </p>
     * 
     * @param key Key
     * @param defaultValue Default value
     * @return <code>CBORObject</code> or <code>defaultValue</code>
     */
    public CBORObject getConditionally(CBORObject key, CBORObject defaultValue) {
       Entry entry = lookup(key, false);
       return entry == null ? defaultValue : entry.value; 
    }

    /**
     * Checks map for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean containsKey(CBORObject key) {
        return lookup(key, false) != null;
    }

    /**
     * Removes mapped object.
     * <p>
     * If <code>key</code> is not present, a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key
     * @return The <code>CBORObject</code> mapped by <code>key</code>
     */
    public CBORObject remove(CBORObject key) {
        byte[] encodedKey = getKey(key).encode();
        Entry precedingEntry = null;
        for (Entry entry = root; entry != null; entry = entry.next) {
            int diff = entry.compare(encodedKey);
            if (diff == 0) {
                if (precedingEntry == null) {
                    // Remove root key.  It may be alone.
                    root = entry.next;
                } else {
                    // Remove key somewhere above root.
                    precedingEntry.next = entry.next;
                }
                numberOfEntries--;
                return entry.value;
            }
            precedingEntry = entry;
        }
        cborError(STDERR_MISSING_KEY + key);
        return null;
    }

    /**
     * Enumerates all keys in a map.
     * 
     * @return Array of keys
     */
    public CBORObject[] getKeys() {
        CBORObject[] keys = new CBORObject[numberOfEntries];
        int i = 0;
        for (Entry entry = root; entry != null; entry = entry.next) {
            keys[i++] = entry.key;
        }
        return keys;
    }

    @Override
    byte[] internalEncode() {
        byte[] encoded = encodeTagAndN(MT_MAP, numberOfEntries);
        for (Entry entry = root; entry != null; entry = entry.next) {
            encoded = addByteArrays(encoded,
                                    addByteArrays(entry.encodedKey, entry.value.encode()));
        }
        return encoded;
    }
        
    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.beginMap();
        boolean notFirst = false;
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (notFirst) {
                cborPrinter.append(',');
            }
            notFirst = true;
            cborPrinter.newlineAndIndent();
            entry.key.internalToString(cborPrinter);
            cborPrinter.append(':');
            cborPrinter.space();
            entry.value.internalToString(cborPrinter);
        }
        cborPrinter.endMap(notFirst);
    }
    
    static final String STDERR_NON_DET_SORT_ORDER =
            "Non-deterministic sort order for map key: ";
    
    static final String STDERR_DUPLICATE_KEY = 
            "Duplicate key: ";

    static final String STDERR_MISSING_KEY = 
            "Missing key: ";
}

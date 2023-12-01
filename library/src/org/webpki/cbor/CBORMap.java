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

/**
 * Class for holding CBOR <code>map</code> objects.
 */
public class CBORMap extends CBORObject {

    boolean preSortedKeys;
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
        
        boolean compareAndTest(byte[] testKey) {
            int diff = compare(testKey);
            if (diff == 0) {
                cborError(STDERR_DUPLICATE_KEY + key);
            }
            return diff > 0;
        }
    }

    /**
     * Creates an empty CBOR <code>map</code>.
     * <p>
     * This constructor provides an opportunity using keys that are <i>sorted</i> 
     * (in lexicographic order), which in maps with many keys can 
     * offer a performance improvement.
     * </p>
     * 
     * @param preSortedKeys If <code>true</code>, keys <b>must</b> be
     * sorted.  If a key is not properly sorted when calling
     * {@link #set(CBORObject, CBORObject)}, a {@link CBORException} is thrown.
     */
    public CBORMap(boolean preSortedKeys) {
        super(CBORTypes.MAP);
        this.preSortedKeys = preSortedKeys;
    }

    /**
     * Creates an empty CBOR <code>map</code>.
     * <p>
     * Equivalent to <code>CBORMap(false)</code>.
     * </p>
     */
    public CBORMap() {
        this(false);
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
            lastEntry = root = newEntry;
        } else {
            // Keys are always sorted, making the verification process simple.
            if (preSortedKeys) {
                // Normal case for parsing.
                if (lastEntry.compareAndTest(newEntry.encodedKey)) {
                    cborError(STDERR_NON_DET_SORT_ORDER + key);
                }
                lastEntry.next = newEntry;
                lastEntry = newEntry;
             } else {
                // Programmatically created key or the result of unconstrained parsing.
                // Then we need to test and sort (always produce deterministic CBOR).
                // The algorithm is based on binary search and sort.
                Entry targetEntry = root;
                boolean below = false;
                int n = numberOfEntries;
                do {
                    int nSave = n;
                    Entry savePoint = targetEntry;
                    // Cut the search span in two halves.
                    n >>= 1;
                    for (int q = 0; q < n && targetEntry.next != null; q++) {
                        targetEntry = targetEntry.next;
                    }
                    if (below = targetEntry.compareAndTest(newEntry.encodedKey)) {
                        // Right half. Tighten interval.
                        targetEntry = savePoint;
                    } else {
                        // Wrong half. Move forward.
                        if (targetEntry.next == null || nSave <= 1) {
                            // Done.
                            break;
                        }
                        n = nSave;
                    }
                } while (n > 0);
                if (below) {
                    // Below current root. Create new root.
                    newEntry.next = root;
                    root = newEntry;
                } else {
                    // "Normal" insert above.
                    Entry nextEntry = targetEntry.next;
                    targetEntry.next = newEntry;
                    newEntry.next = nextEntry;
                }  
            }
        }
        numberOfEntries++;
        return this;
    }

    private Entry lookup(CBORObject key, boolean mustExist) {
        byte[] encodedKey = getKey(key).encode();
        if (root != null) {
            Entry targetEntry = root;
            int n = numberOfEntries;
            // The algorithm is based on binary search.
            do {
                int nSave = n;
                Entry savePoint = targetEntry;
                // Cut the search span in two halves.
                n >>= 1;
                for (int q = 0; q < n && targetEntry.next != null; q++) {
                    targetEntry = targetEntry.next;
                }
                int diff = targetEntry.compare(encodedKey);
                if (diff == 0) {
                    // We got it!
                    return targetEntry;
                }
                if (diff > 0) {
                    // Right half. Tighten interval.
                    targetEntry = savePoint;
                } else {
                    // Wrong half. Move forward.
                    if (targetEntry.next == null || nSave <= 1) {
                        // Sorry, no match.
                        break;
                    }
                    n = nSave;
                }
            } while (n > 0);
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
        Entry targetEntry = lookup(key, true);
        Entry precedingEntry = null;
        for (Entry entry = root; entry != null; entry = entry.next) {
            if (entry == targetEntry) {
                if (precedingEntry == null) {
                    // Remove root key.  It may be alone.
                    root = entry.next;
                } else {
                    // Remove key somewhere above root.
                    precedingEntry.next = entry.next;
                }
                break;
            }
            precedingEntry = entry;
        }
        numberOfEntries--;
        return targetEntry.value;
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

/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import java.util.ArrayList;
import java.util.Arrays;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>map</code> objects.
 * <p>
 * Note: to maintain
 * <a href='package-summary.html#deterministic-encoding'>Deterministic&nbsp;Encoding</a>
 * <code>map</code> keys are <i>automatically sorted during insertion</i>.
 * </p>
 */
public class CBORMap extends CBORObject {

    boolean preSortedKeys;

    // Similar to the Java Map.Entry but optimized for CBOR. 
    static class Entry {
        CBORObject key;
        CBORObject value;
        byte[] encodedKey;
         
        Entry(CBORObject key, CBORObject object) {
            this.key = key;
            this.value = object;
            this.encodedKey = key.encode();
        }
        
        int compare(byte[] testKey) {
            return Arrays.compareUnsigned(encodedKey, testKey);
        }
        
        boolean compareAndTest(Entry entry) {
            int diff = compare(entry.encodedKey);
            if (diff == 0) {
                cborError(STDERR_DUPLICATE_KEY + key);
            }
            return diff > 0;
        }
    }

    ArrayList<Entry> entries = new ArrayList<>();

    /**
     * Creates an empty CBOR <code>map</code>.
     * <p>
     * Equivalent to <code>CBORMap().setSortingMode(false)</code>.
     * </p>
     */
    public CBORMap() {}

    private CBORObject getKey(CBORObject key) {
        nullCheck(key);
        return key;
    }
    
    /**
     * Get size of the CBOR <code>map</code>.
     * 
     * @return The number of entries (keys) in the map
     */
    public int size() {
        return entries.size();
    }

    /**
     * Set mapped CBOR object.
     * <p>
     * If <code>key</code> is already present, a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key
     * @param value Value
     * @return <code>this</code>
     * @throws CBORException
     */
    public CBORMap set(CBORObject key, CBORObject value) {
        key = getKey(key);
        nullCheck(value);
        Entry newEntry = new Entry(key, value);
        int insertIndex = entries.size();
        // Keys are always sorted, making the verification process simple.
        // First element? Just insert.
        if (insertIndex > 0) {
            int endIndex = insertIndex - 1;
            if (preSortedKeys) {
                // Normal case for determinstic decoding.
                if (entries.get(endIndex).compareAndTest(newEntry)) {
                    cborError(STDERR_NON_DET_SORT_ORDER + key);
                }
            } else {
                // Programmatically created key or the result of unconstrained decoding.
                // Then we need to test and sort (always produce deterministic CBOR).
                // The algorithm is based on binary sort and insertion.
                insertIndex = 0;
                int startIndex = 0;
                while (startIndex <= endIndex) {
                    int midIndex = (endIndex + startIndex) / 2;
                    if (newEntry.compareAndTest(entries.get(midIndex))) {
                        // New key is bigger than the looked up entry.
                        // Preliminary assumption: this is the one, but continue.
                        insertIndex = startIndex = midIndex + 1;
                    } else {
                        // New key is smaller, search lower parts of the array.
                        endIndex = midIndex - 1;
                    }
                }
            }
        }
        // If insertIndex == entries.size(), the key will be appended.
        // If insertIndex == 0, the key will be first in the list.
        entries.add(insertIndex, newEntry);
        return this;
    }

    /**
     * Set sorting mode for the CBOR <code>map</code>.
     * <p>
     * This method provides an opportunity using keys that are <i>presorted</i> 
     * (in lexicographic order), which in maps with many keys can 
     * offer performance improvements.
     * </p>
     * <p>
     * Note that <code>setSortingMode</code> is only effective during <i>encoding</i>.
     * The <code>setSortingMode</code> method may be called multiple times,
     * permitting certain keys to be automatically sorted and others
     * to be provided in a presorted fashion.
     * See also {@link CBORDecoder#setDeterministicMode(boolean)}.
     * </p>
     *  
     * @param preSortedKeys If <code>true</code>, keys <b>must</b> be
     * sorted.  If a key is not properly sorted when calling
     * {@link #set(CBORObject, CBORObject)}, a {@link CBORException} is thrown.
     * @return <code>this</code>
     */
    public CBORMap setSortingMode(boolean preSortedKeys) {
        this.preSortedKeys = preSortedKeys;
        return this;
    }
    
    private Entry lookup(CBORObject key, boolean mustExist) {
        byte[] encodedKey = getKey(key).encode();
        int startIndex = 0;
        int endIndex = entries.size() - 1;
        while (startIndex <= endIndex) {
            int midIndex = (endIndex + startIndex) / 2;
            Entry entry = entries.get(midIndex);
            int diff = entry.compare(encodedKey);
            if (diff == 0) {
                return entry;
            }
            if (diff < 0) {
                startIndex = midIndex + 1;
            } else {
                endIndex = midIndex - 1;
            }
        }
        if (mustExist) {
            cborError(STDERR_MISSING_KEY + key);
        }
        return null;
    }

    /**
     * Get mapped CBOR object.
     * <p>
     * If <code>key</code> is present, the associated <code>value</code> is returned,
     * else a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key
     * @return <code>value</code>
     * @throws CBORException
     */
    public CBORObject get(CBORObject key) {
        return lookup(key, true).value;
    }

    /**
     * Get mapped CBOR object conditionally.
     * <p>
     * If <code>key</code> is present, the associated <code>value</code> is returned,
     * else <code>defaultValue</code> is returned.
     * Note: <code>defaultValue</code> may be <code>null</code>.
     * </p>
     * 
     * @param key Key
     * @param defaultValue Default value
     * @return <code>value</code> or <code>defaultValue</code>
     */
    public CBORObject getConditionally(CBORObject key, CBORObject defaultValue) {
        Entry entry = lookup(key, false);
        return entry == null ? defaultValue : entry.value; 
    }

    /**
     * Check CBOR <code>map</code> for key presence.
     * 
     * @param key Key
     * @return <code>true</code> if the key is present
     */
    public boolean containsKey(CBORObject key) {
        return lookup(key, false) != null;
    }

    /**
     * Remove mapped CBOR object.
     * <p>
     * If <code>key</code> is present, the associated <code>value</code> is returned,
     * else a {@link CBORException} is thrown.
     * </p>
     * <p>
     * After saving <code>value</code> for return, the <code>key</code> and its
     * associated <code>value</code> are removed.
     * </p>
     * 
     * @param key Key
     * @return <code>value</code>
     * @throws CBORException
     */
    public CBORObject remove(CBORObject key) {
        Entry targetEntry = lookup(key, true);
        for (int i = 0; i < entries.size(); i++) {
            if (entries.get(i) == targetEntry) {
                entries.remove(i);
                break;
            }
        }
        return targetEntry.value;
    }

    /**
     * Enumerate all keys in the CBOR <code>map</code>.
     * <p>
     * Note: the keys are returned in proper sort order.
     * </p>
     * 
     * @return Array of keys
     */
    public CBORObject[] getKeys() {
        ArrayList<CBORObject> keys = new ArrayList<>(entries.size());
        for (Entry entry : entries) {
            keys.add(entry.key);
        }
        return keys.toArray(new CBORObject[0]);
    }

    @Override
    byte[] internalEncode() {
        byte[] encoded = encodeTagAndN(MT_MAP, entries.size());
        for (Entry entry : entries) {
            encoded = addByteArrays(encoded,
                                    addByteArrays(entry.encodedKey, entry.value.encode()));
        }
        return encoded;
    }
        
    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.beginMap();
        boolean notFirst = false;
        for (Entry entry : entries) {
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

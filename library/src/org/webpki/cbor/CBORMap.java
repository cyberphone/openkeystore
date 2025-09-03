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

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Arrays;

import static org.webpki.cbor.CBORInternal.*;

/**
 * Class for holding CBOR <code>{}</code> (map) objects.
 * <p>
 * Note: to maintain
 * <a href='package-summary.html#deterministic-encoding' class='webpkilink'>Deterministic&nbsp;Encoding</a>
 * map keys are <i>automatically sorted during insertion</i>.
 * </p>
 */
public class CBORMap extends CBORObject {

    /**
     * Support interface for dynamic CBOR generation.
     * <p>
     * Also see {@link #setDynamic(Dynamic)}.
     * </p>
     */
    public interface Dynamic {

        public CBORMap set(CBORMap wr);

    }

    private boolean preSortedKeys;

    // Similar to the Java Map.Entry but optimized for CBOR. 
    static class Entry {
        CBORObject key;
        CBORObject object;
        byte[] encodedKey;
         
        Entry(CBORObject key, CBORObject object) {
            this.key = key;
            this.object = object;
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
     * Creates an empty CBOR <code>{}</code> (map).
     * <p>
     * Equivalent to <code>CBORMap().setSortingMode(false)</code>.
     * </p>
     */
    public CBORMap() {}
    
    /**
     * Get size of the CBOR map.
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
     * <p>
     * Note that this implementation presumes that <code>key</code> objects
     * are <i>immutable</i>.  To create <code>key</code> objects
     * of arbitrary complexity,  <code>key</code> objects <b>must</b>
     * either be created <i>inline</i> (using chaining), or be supplied as
     * <i>preset variables</i>.
     * </p>
     * Also see {@link CBORMap#update(CBORObject, CBORObject, boolean)}.
     * <p>
     * </p>
     * 
     * @param key Key (name)
     * @param object Object (value)
     * @return <code>this</code>
     * @throws CBORException
     */
    public CBORMap set(CBORObject key, CBORObject object) {
        immutableTest();
        // Create a map entry object.
        Entry newEntry = new Entry(checkObject(key), checkObject(object));
        // Keys are immutable.
        makeImmutable(key);
        // Insert the entry object in the proper position in the map.
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
     * Set CBOR data using an external (dynamic) interface.
     * <p></p>
     * Sample using a construct suitable for chained writing:
     * <div class='webpkifloat'>
     * <pre>  setDynamic((wr) -&gt; optionalString == null ? wr : wr.set(KEY, new CBORString(optionalString)));</pre>
     * </div>
     * @param dynamic Interface (usually Lambda)
     * @return <code>this</code>
     * @throws CBORException
     */
    public CBORMap setDynamic(Dynamic dynamic) {
        return dynamic.set(this);
    }

    /**
     * Merge CBOR map.
     * <p>
     * Note that a duplicate key causes a {@link CBORException} to be thrown.
     * </p>
     * 
     * @param map Map to be merged into the current mao
     * @return <code>this</code>
     * @throws CBORException
     */
    public CBORMap merge(CBORMap map) {
        immutableTest();
        for (Entry entry : map.entries.toArray(new Entry[0])) {
            set(entry.key, entry.object);
        }
        return this;
    }

    /**
     * Set sorting mode for the CBOR map.
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
     * See also {@link CBORDecoder#CBORDecoder(InputStream, int, int)}.
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

    private int lastLookup;

    private Entry lookup(CBORObject key, boolean mustExist) {
        byte[] encodedKey = checkObject(key).encode();
        int startIndex = 0;
        int endIndex = entries.size() - 1;
        while (startIndex <= endIndex) {
            int midIndex = (endIndex + startIndex) / 2;
            Entry entry = entries.get(midIndex);
            int diff = entry.compare(encodedKey);
            if (diff == 0) {
                lastLookup = midIndex;
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
     * If <code>key</code> is present, the associated <code>object</code> is returned,
     * else a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key (name)
     * @return <code>object</code>
     * @throws CBORException
     */
    public CBORObject get(CBORObject key) {
        return lookup(key, true).object;
    }

    /**
     * Get mapped CBOR object conditionally.
     * <p>
     * If <code>key</code> is present, the associated <code>object</code> is returned,
     * else <code>defaultObject</code> is returned.
     * Note: <code>defaultObject</code> may be <code>null</code>.
     * </p>
     * 
     * @param key Key (name)
     * @param defaultObject Default object (value)
     * @return <code>object</code> or <code>defaultObject</code>
     */
    public CBORObject getConditionally(CBORObject key, CBORObject defaultObject) {
        Entry entry = lookup(key, false);
        return entry == null ? defaultObject : entry.object; 
    }

    /**
     * Check CBOR map for key presence.
     * 
     * @param key Key (name)
     * @return <code>true</code> if the key is present
     */
    public boolean containsKey(CBORObject key) {
        return lookup(key, false) != null;
    }

    /**
     * Remove mapped CBOR object.
     * <p>
     * If <code>key</code> is present, the <code>key</code> and
     * associated <code>object</code> are removed,
     * else a {@link CBORException} is thrown.
     * </p>
     * 
     * @param key Key (name)
     * @return Removed object (value)
     * @throws CBORException
     */
    public CBORObject remove(CBORObject key) {
        immutableTest();
        Entry targetEntry = lookup(key, true);
        entries.remove(lastLookup);
        return targetEntry.object;
    }

    /**
     * Update mapped CBOR object.
     * <p>
     * If <code>existing</code> is <code>true</code>, <code>key</code> must already be present,
     * else a {@link CBORException} is thrown.
     * </p>
     * <p>
     * If <code>existing</code> is <code>false</code>, a map entry for <code>key</code>
     * will be created if not already present.
     * </p>
     * 
     * @param key Key (name)
     * @param object New object (value)
     * @param existing Flag
     * @return Previous <code>object</code>.  May be <code>null</code>.
     * @throws CBORException
     */
    public CBORObject update(CBORObject key, CBORObject object, boolean existing) {
        immutableTest();
        Entry targetEntry = lookup(key, existing);
        CBORObject previous;
        if (targetEntry == null) {
            previous = null;
            set(key, object);
        } else {
            previous = targetEntry.object;
            targetEntry.object = checkObject(object);
        }
        return previous;
    }  

    /**
     * Enumerate all keys in the CBOR map.
     * <p>
     * Note: the keys are returned in proper sort order.
     * </p>
     * 
     * @return Array of keys
     */
    public ArrayList<CBORObject> getKeys() {
        ArrayList<CBORObject> keys = new ArrayList<>(entries.size());
        for (Entry entry : entries) {
            keys.add(entry.key);
        }
        return keys;
    }

    @Override
    byte[] internalEncode() {
        byte[] encoded = encodeTagAndN(MT_MAP, entries.size());
        for (Entry entry : entries) {
            encoded = CBORUtil.concatByteArrays(encoded,
                                                entry.encodedKey,
                                                entry.object.internalEncode());
        }
        return encoded;
    }
        
    @Override
    void internalToString(CborPrinter cborPrinter) {
        cborPrinter.beginList('{');
        boolean notFirst = false;
        for (Entry entry : entries) {
            if (notFirst) {
                cborPrinter.append(',');
            }
            notFirst = true;
            cborPrinter.newlineAndIndent();
            entry.key.internalToString(cborPrinter);
            cborPrinter.append(':').space();
            entry.object.internalToString(cborPrinter);
        }
        cborPrinter.endList(notFirst, '}');
    }
    
    static final String STDERR_NON_DET_SORT_ORDER =
            "Non-deterministic sort order for map key: ";
    
    static final String STDERR_DUPLICATE_KEY = 
            "Duplicate key: ";

    static final String STDERR_MISSING_KEY = 
            "Missing key: ";
}

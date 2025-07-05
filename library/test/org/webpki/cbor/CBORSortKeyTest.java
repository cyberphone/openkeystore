package org.webpki.cbor;

import java.util.Arrays;

// Test program for the "preSortedKeys" CBORMap option

public class CBORSortKeyTest {

    static int TOTAL_SET_OPERATIONS = 1000000;

    static int SMALL_MAP  = 10;
    static int MEDIUM_MAP = 25;
    
    static CBORInt[] SORTED_KEYS = new CBORInt[TOTAL_SET_OPERATIONS];
    static CBORInt[] VALUES = new CBORInt[TOTAL_SET_OPERATIONS];
    
    static {
        for (int q = 0; q < TOTAL_SET_OPERATIONS; q++) {
            CBORInt key = new CBORInt(q);
            SORTED_KEYS[q] = key;
            VALUES[q] = new CBORInt(q); 
        }
    }

    static class Entry {
        CBORObject key;
        CBORObject value;
        byte[] encoded;
    }
    
    static void printTime(String label, int mapSize, long startTime, boolean sortFlag) {
        System.out.printf("%s(%d) %s map execution time=%d ms\n",
                          label,
                          mapSize,
                          sortFlag ? "sorted" : "unsorted",
                          System.currentTimeMillis() - startTime);
        
    }
    
    static void bigMap(boolean sortFlag) {
        long startTime = System.currentTimeMillis();
        CBORMap map = new CBORMap().setSortingMode(sortFlag);
        int q = 0;
        for (CBORInt key : SORTED_KEYS) {
            map.set(key, VALUES[q++]);
        }
        printTime("SET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        for (int n = 0; n < TOTAL_SET_OPERATIONS ; n++) {
            if (map.get(SORTED_KEYS[n]).getInt32() != n) {
                CBORInternal.cborError("Big access");
            }
        }
        printTime("GET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        if (sortFlag) return;
        map = new CBORMap();
        for (int n = TOTAL_SET_OPERATIONS; --n >= 0;) {
            map.set(SORTED_KEYS[n], VALUES[n]);
        }
        printTime("Reverse SET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
         for (int n = TOTAL_SET_OPERATIONS; --n >= 0;) {
            if (map.get(SORTED_KEYS[n]).getInt32() != n) {
                CBORInternal.cborError("Big access");
            }
        }
        printTime("Reverse GET", TOTAL_SET_OPERATIONS, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        if (map.remove(SORTED_KEYS[TOTAL_SET_OPERATIONS/4]).getInt32() != TOTAL_SET_OPERATIONS/4) {
            CBORInternal.cborError("Big access");
        }
        printTime("Remove", TOTAL_SET_OPERATIONS, startTime, sortFlag);
    }
    
    static void multipleSmallMaps(int mapSize, boolean sortFlag) {
        CBORMap map = null;
        int maps = TOTAL_SET_OPERATIONS / mapSize;
    
        long startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            map = new CBORMap().setSortingMode(sortFlag);
            for (int n = 0; n < mapSize; n++) {
                map.set(SORTED_KEYS[n], VALUES[n]);
            }            
        }
        printTime("SET", mapSize, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            for (int n = 0; n < mapSize; n++) {
                if (map.get(SORTED_KEYS[n]).getInt32() != n) {
                    CBORInternal.cborError("Medium access");
                }
            }            
        }
        printTime("GET", mapSize, startTime, sortFlag);

        if (!sortFlag) return;

        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Speedy option?
            Entry staticArray[] = new Entry[mapSize];
            for (int n = 0; n < mapSize; n++) {
                Entry entry = new Entry();
                CBORObject key = SORTED_KEYS[n];
                CBORObject value = VALUES[n];
                entry.key = key;
                entry.value = value;
                entry.encoded = key.encode();
                if (n > 0) {
                    if (Arrays.compareUnsigned(staticArray[n - 1].encoded, entry.encoded) > 0) {
                        throw new RuntimeException("Duplicate or badly ordered key");
                    }
                }
                staticArray[n] = entry;
            }            
        }
        printTime("SET naked", mapSize, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            map = new CBORMap();
            for (int n = mapSize; --n >= 0;) {
                map.set(SORTED_KEYS[n], VALUES[n]);
            }            
        }
        printTime("Reverse SET", mapSize, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            for (int n = mapSize; --n >= 0;) {
                if (map.get(SORTED_KEYS[n]).getInt32() != n) {
                    CBORInternal.cborError("Medium access");
                }
            }            
        }
        printTime("Reverse GET", mapSize, startTime, sortFlag);
    }
    
    public static void main(String[] argv)  {
        multipleSmallMaps(SMALL_MAP, true);
        multipleSmallMaps(SMALL_MAP, false);
        System.out.println();

        multipleSmallMaps(MEDIUM_MAP, true);
        multipleSmallMaps(MEDIUM_MAP, false);
        System.out.println();

        bigMap(true);
        bigMap(false);
    }
}

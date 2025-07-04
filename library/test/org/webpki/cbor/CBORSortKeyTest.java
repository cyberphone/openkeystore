package org.webpki.cbor;

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
    
    static void printTime(String label, int mapSize, long startTime, boolean sortFlag) {
        System.out.printf("%s(%d) %s map execution time=%d ms\n",
                          label,
                          mapSize,
                          sortFlag ? "sorted" : "unsorted",
                          System.currentTimeMillis() - startTime);
        
    }
    
    static void bigMap(boolean sortFlag) {
        long startTime = System.currentTimeMillis();
        CBORMap cborMap = new CBORMap().setSortingMode(sortFlag);
        int q = 0;
        for (CBORInt key : SORTED_KEYS) {
            cborMap.set(key, VALUES[q++]);
        }
        printTime("SET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        for (int n = 0; n < TOTAL_SET_OPERATIONS ; n++) {
            if (cborMap.get(SORTED_KEYS[n]).getInt32() != n) {
                CBORInternal.cborError("Big access");
            }
        }
        printTime("GET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        if (sortFlag) return;
        cborMap = new CBORMap();
        for (int n = TOTAL_SET_OPERATIONS; --n >= 0;) {
            cborMap.set(SORTED_KEYS[n], VALUES[n]);
        }
        printTime("Reverse SET", TOTAL_SET_OPERATIONS, startTime, sortFlag);

        startTime = System.currentTimeMillis();
         for (int n = TOTAL_SET_OPERATIONS; --n >= 0;) {
            if (cborMap.get(SORTED_KEYS[n]).getInt32() != n) {
                CBORInternal.cborError("Big access");
            }
        }
        printTime("Reverse GET", TOTAL_SET_OPERATIONS, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        if (cborMap.remove(SORTED_KEYS[TOTAL_SET_OPERATIONS/4]).getInt32() != TOTAL_SET_OPERATIONS/4) {
            CBORInternal.cborError("Big access");
        }
        printTime("Remove", TOTAL_SET_OPERATIONS, startTime, sortFlag);
    }
    
    static void multipleSmallMaps(int mapSize, boolean sortFlag) {
        CBORMap cborMap = null;
        int maps = TOTAL_SET_OPERATIONS / mapSize;
        long startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            cborMap = new CBORMap().setSortingMode(sortFlag);
            for (int n = 0; n < mapSize; n++) {
                cborMap.set(SORTED_KEYS[n], VALUES[n]);
            }            
        }
        printTime("SET", mapSize, startTime, sortFlag);

        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            for (int n = 0; n < mapSize; n++) {
                if (cborMap.get(SORTED_KEYS[n]).getInt32() != n) {
                    CBORInternal.cborError("Medium access");
                }
            }            
        }
        printTime("GET", mapSize, startTime, sortFlag);

        if (sortFlag) return;
        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            cborMap = new CBORMap();
            for (int n = mapSize; --n >= 0;) {
                cborMap.set(SORTED_KEYS[n], VALUES[n]);
            }            
        }
        printTime("Reverse SET", mapSize, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            for (int n = mapSize; --n >= 0;) {
                if (cborMap.get(SORTED_KEYS[n]).getInt32() != n) {
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

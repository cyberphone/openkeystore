package org.webpki.cbor;

// Test program for the "preSortedKeys" CBORMap option

public class CBORSortKeyTest {

    static int TOTAL_SET_OPERATIONS = 1000000;

    static int SMALL_MAP  = 10;
    static int MEDIUM_MAP = 50;
    
    static CBORString[] SORTED_KEYS = new CBORString[TOTAL_SET_OPERATIONS];
    static CBORString[] REVERSE_KEYS = new CBORString[TOTAL_SET_OPERATIONS];
    static CBORInt[] VALUES = new CBORInt[TOTAL_SET_OPERATIONS];
    
    static {
        for (int q = 0; q < TOTAL_SET_OPERATIONS; q++) {
            CBORString key = new CBORString("prefix" + q);
            SORTED_KEYS[q] = key;
            REVERSE_KEYS[TOTAL_SET_OPERATIONS - 1 - q] = key;
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
        CBORMap cborMap = new CBORMap(sortFlag);
        int q = 0;
        for (CBORString key : SORTED_KEYS) {
            cborMap.set(key, VALUES[q++]);
        }
        printTime("Big", TOTAL_SET_OPERATIONS, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        for (int n = 0; n < TOTAL_SET_OPERATIONS ; n++) {
            if (cborMap.get(SORTED_KEYS[n]).getInt() != n) {
                CBORObject.cborError("Big access");
            }
        }
        printTime("Access big", TOTAL_SET_OPERATIONS, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        if (sortFlag) return;
        cborMap = new CBORMap();
        q = 0;
        for (CBORString key : REVERSE_KEYS) {
            cborMap.set(key, VALUES[q++]);
        }
        printTime("Reverse big", TOTAL_SET_OPERATIONS, startTime, sortFlag);
    }
    
    static void multipleSmallMaps(int mapSize, boolean sortFlag) {
        CBORMap cborMap = null;;
        long startTime = System.currentTimeMillis();
        int maps = TOTAL_SET_OPERATIONS / mapSize;
        CBORString[] keys = sortFlag ? SORTED_KEYS : REVERSE_KEYS;
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            cborMap = new CBORMap(sortFlag);
            for (int n = 0; n < mapSize; n++) {
                cborMap.set(keys[n], VALUES[n]);
            }            
        }
        printTime(mapSize == SMALL_MAP ? "Small" : "Medium", mapSize, startTime, sortFlag);
        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            for (int n = 0; n < mapSize; n++) {
                if (cborMap.get(keys[n]).getInt() != n) {
                    CBORObject.cborError("Medium access");
                }
            }            
        }
        printTime(mapSize == SMALL_MAP ? "Access small" : "Access medium", mapSize, startTime, sortFlag);
        if (sortFlag) return;
        startTime = System.currentTimeMillis();
        for (int q = 0; q < maps; q++) {
            // Creating a CBORMap object is a heavy operation
            cborMap = new CBORMap();
            for (int n = 0; n < mapSize; n++) {
                cborMap.set(REVERSE_KEYS[n], VALUES[n]);
            }            
        }
        printTime(mapSize == SMALL_MAP ? "Reverse small" : "Reverse medium", mapSize, startTime, sortFlag);
    }
    
    public static void main(String[] argv)  {
        multipleSmallMaps(SMALL_MAP, false);
        multipleSmallMaps(SMALL_MAP, true);
        multipleSmallMaps(MEDIUM_MAP, false);
        multipleSmallMaps(MEDIUM_MAP, true);
        bigMap(false);
        bigMap(true);
    }
}

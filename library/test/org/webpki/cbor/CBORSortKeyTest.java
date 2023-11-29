package org.webpki.cbor;

// Test program for the "preSortedKeys" CBORMap option

public class CBORSortKeyTest {
    static CBORString VALUE = new CBORString("hi");
    
    static int TOTAL_SET_OPERATIONS = 100000;

    static int SMALL_MAP  = 10;
    static int MEDIUM_MAP = 50;
    
    static CBORInt[] SORTED_KEYS = new CBORInt[TOTAL_SET_OPERATIONS];
    
    static {
        for (int q = 0; q < TOTAL_SET_OPERATIONS; q++) {
            SORTED_KEYS[q] = new CBORInt(q); 
        }
    }
    
    static void printTime(String label, int mapSize, long startTime, boolean sortFlag) {
        System.out.printf("%s(%d) %s map execution time=%d\n",
                          label,
                          mapSize,
                          sortFlag ? "sorted" : "unsorted",
                          System.currentTimeMillis() - startTime);
        
    }
    
    static void bigMap(boolean sortFlag) {
        long startTime = System.currentTimeMillis();
        CBORMap cborMap = new CBORMap(sortFlag);
        for (CBORInt key : SORTED_KEYS) {
            cborMap.set(key, VALUE);
        }
        printTime("Big", TOTAL_SET_OPERATIONS, startTime, sortFlag);
    }
    
    static void multipleSmallMaps(int mapSize, boolean sortFlag) {
        long startTime = System.currentTimeMillis();
        int maps = TOTAL_SET_OPERATIONS / mapSize;
        for (int q = 0; q < maps; q++) {
            CBORMap cborMap = new CBORMap(sortFlag);
            for (int n = 0; n < mapSize; n++) {
                cborMap.set(SORTED_KEYS[n], VALUE);
            }            
        }
        printTime(mapSize == SMALL_MAP ? "Small" : "Medium", mapSize, startTime, sortFlag);
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

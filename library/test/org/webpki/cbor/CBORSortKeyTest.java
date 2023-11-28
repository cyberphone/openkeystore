package org.webpki.cbor;

public class CBORSortKeyTest {
    static CBORString VALUE = new CBORString("hi");
    
    static int SMALL  = 10;
    static int MEDIUM = 50;
    
    static CBORInt[] SORTED = new CBORInt[1000000];
    
    static {
        for (int q = 0; q < SORTED.length; q++) {
            SORTED[q] = new CBORInt(q); 
        }
    }
    
    static void printTime(String size, long start, boolean sortFlag) {
        System.out.println(String.format("%s %s map execution time=%d",
                                         size,
                                         sortFlag ? "sorted" : "unsorted",
                                         System.currentTimeMillis() - start));
        
    }
    
    static void bigMap(boolean sortFlag) {
        long start = System.currentTimeMillis();
        CBORMap cborMap = new CBORMap(sortFlag);
        for (CBORInt key : SORTED) {
            cborMap.set(key, VALUE);
        }
        printTime("Big(1000000)", start, sortFlag);
    }
    
    static void multipleSmallMaps(int size, boolean sortFlag) {
        long start = System.currentTimeMillis();
        int turns = SORTED.length / size;
        for (int q = 0; q < turns; q++) {
            CBORMap cborMap = new CBORMap(sortFlag);
            for (int n = 0; n < size; n++) {
                cborMap.set(SORTED[n], VALUE);
            }            
        }
        printTime((size == SMALL ? "Small" : "Medium") + "(" + size + ")", start, sortFlag);
    }    

    public static void main(String[] argv)  {
        multipleSmallMaps(SMALL, false);
        multipleSmallMaps(SMALL, true);
        multipleSmallMaps(MEDIUM, false);
        multipleSmallMaps(MEDIUM, true);
        bigMap(false);
        bigMap(true);
    }
}

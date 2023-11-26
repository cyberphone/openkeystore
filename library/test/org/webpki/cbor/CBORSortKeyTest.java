package org.webpki.cbor;

public class CBORSortKeyTest {
    static CBORString value = new CBORString("hi");
    
    static CBORInt[] sorted = new CBORInt[1000000];
    
    static {
        for (int q = 0; q < sorted.length; q++) {
            sorted[q] = new CBORInt(q); 
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
        for (CBORInt key : sorted) {
            cborMap.set(key, value);
        }
        printTime("Big(1000000)", start, sortFlag);
    }
    
    static void multipleSmallMaps(boolean smallFlag, boolean sortFlag) {
        long start = System.currentTimeMillis();
        int size = smallFlag ? 10 : 50;
        for (int q = 0; q < 1000000; q++) {
            CBORMap cborMap = new CBORMap(sortFlag);
            for (int n = 0; n < size; n++) {
                cborMap.set(sorted[n], value);
            }            
        }
        printTime(smallFlag ? "Small(10)" : "Medium(50)", start, sortFlag);
    }    

    public static void main(String[] argv)  {
        multipleSmallMaps(true, false);
        multipleSmallMaps(true, true);
        multipleSmallMaps(false, false);
        multipleSmallMaps(false, true);
        bigMap(false);
        bigMap(true);
    }
}

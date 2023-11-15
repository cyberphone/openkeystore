package org.webpki.cbor;

public class CBORSortKeyTest {
    static CBORString value = new CBORString("hi");
    
    static CBORInt[] sorted = new CBORInt[1000000];
    
    static {
        for (int q = 0; q < sorted.length; q++) {
            sorted[q] = new CBORInt(q); 
        }
    }
    
    static void oneRun(CBORMap cborMap) {
        long start = System.currentTimeMillis();
        for (CBORInt key : sorted) {
            cborMap.set(key, value);
        }
        System.out.println("Time=" + (System.currentTimeMillis() - start));
    }
    
    public static void main(String[] argv)  {
        oneRun(new CBORMap());
        oneRun(new CBORMap(true));
    }
}

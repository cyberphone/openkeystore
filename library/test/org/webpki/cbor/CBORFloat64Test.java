package org.webpki.cbor;

import java.util.Random;

public class CBORFloat64Test {
    
    static int float64;
    static int float32;
    static int float16;
    static int runs;
    
    static void convert (long l) {
        try {
            double d = Double.longBitsToDouble(l);
            CBORDouble cbor = new CBORDouble(d);
            switch (cbor.tag) {
                case CBORObject.MT_FLOAT16:
                    if (Double.isNaN(d)) break;
                    if (Double.isInfinite(d)) break;
                    float16++;
                    break;
                case CBORObject.MT_FLOAT32:
                    float32++;
                    break;
                case CBORObject.MT_FLOAT64:
                    float64++;
                    break;
                default:
                    throw new RuntimeException("BUG");
            }
            double v = CBORObject.decode(cbor.encode()).getDouble();
            if ((++runs % 1000000) == 0) {
                System.out.println("V=" + d + " 16=" + float16 + " 32=" + float32 + " 64=" + float64);
            }
        } catch (Exception e) {
            System.out.println("**********=" + Long.toUnsignedString(l, 16));
            System.exit(3);
        }
    }
    
    public static void main(String[] argv)  {
        Random random = new Random();
        while (true) {
            long l = random.nextLong();
            convert(l);
        }
    }
}
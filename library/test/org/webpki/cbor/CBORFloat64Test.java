package org.webpki.cbor;

import java.util.Random;

public class CBORFloat64Test {
    
    static long float64;
    static long float32;
    static long float16;
    static long runs;
    
    static void convert (long l, boolean float32Flag) {
        try {
            double d = float32Flag ? Float.intBitsToFloat((int) l) : Double.longBitsToDouble(l);
            CBORFloat cbor = new CBORFloat(d);
            switch (cbor.tag) {
                case CBORObject.MT_FLOAT16:
                    float16++;
                    break;
                case CBORObject.MT_FLOAT32:
                    float32++;
                    break;
                case CBORObject.MT_FLOAT64:
                    float64++;
                    if (float32Flag) {
                        throw new RuntimeException("BUG");
                    }
                    break;
                default:
                    throw new RuntimeException("BUG");
            }
            Double v = CBORObject.decode(cbor.encode()).getDouble();
            if (v.compareTo(d) != 0) {
                throw new RuntimeException ("Fail");
            }
            if ((++runs % 1000000) == 0) {
                System.out.println("16=" + float16 + " 32=" + float32 + " 64=" + float64);
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
            convert(l, false);
            convert(l, true);
        }
    }
}

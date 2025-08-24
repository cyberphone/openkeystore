package org.webpki.cbor;

import static org.webpki.cbor.CBORInternal.*;

public class CBORFloat32Test {
    
    static long float32;
    static long float16;
    static long runs;
    
    static void convert (long i) {
        boolean genuine = true;
        boolean simple = true;
        byte[] cbor = null;
        CBORNonFinite nf = null;
        try {
            if ((i & CBORInternal.FLOAT32_POS_INFINITY) == CBORInternal.FLOAT32_POS_INFINITY) {
                nf = new CBORNonFinite(i);
                genuine = false;
                simple = nf.isSimple();
                cbor = nf.encode();
            }
            if (simple) {
                cbor = CBORFloat.createExtendedFloat(Float.intBitsToFloat((int)i)).encode();
            }
            switch (cbor.length) {
                case 3:
                    float16++;
                    break;
                case 5:
                    float32++;
                    break;
                default:
                    throw new RuntimeException("BUG");
            }
            CBORObject object = CBORDecoder.decode(cbor);
            if (simple) {
                double d = Float.intBitsToFloat((int)i);
                Double v = object.getExtendedFloat64();
                if (v.compareTo(d) != 0) {
                    throw new RuntimeException ("Fail");
                }
                if (genuine) {
                    v = object.getFloat64();
                    if (v.compareTo(d) != 0) {
                        throw new RuntimeException ("Fail2");
                    }
                }
            } else {
                if ((((nf.getNonFinite64() >> 
                    (FLOAT64_SIGNIFICAND_SIZE - FLOAT32_SIGNIFICAND_SIZE)) ^ i) &
                    ((1 << FLOAT32_SIGNIFICAND_SIZE) - 1)) != 0) {
                    throw new RuntimeException ("Fail3");
                }
            }
            if ((++runs % 1000000) == 0) {
                System.out.println(" 16=" + float16 + " 32=" + float32);
            }
        } catch (Exception e) {
            System.out.println("**********=" + Long.toUnsignedString(i, 16) + " e=" + e.getMessage());
            System.exit(3);
        }
    }
    
    public static void main(String[] argv)  {
        long f = 0;
        while (f < (FLOAT32_NEG_ZERO << 1)) {
            convert(f++);
        }
        System.out.println("Runs=" + Long.toString(runs));
    }
}

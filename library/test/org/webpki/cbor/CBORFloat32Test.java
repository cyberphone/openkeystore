package org.webpki.cbor;

public class CBORFloat32Test {
    
    static int float32;
    static int float16;
    static int runs;
    
    static void convert (int i) {
        try {
            double d = Float.intBitsToFloat(i);
            CBORFloat cbor = new CBORFloat(d);
            switch (cbor.tag) {
                case CBORObject.MT_FLOAT16:
                    float16++;
                    break;
                case CBORObject.MT_FLOAT32:
                    float32++;
                    break;
                default:
                    throw new RuntimeException("BUG");
            }
            Double v = CBORObject.decode(cbor.encode()).getFloat64();
            if (v.compareTo(d) != 0) {
                throw new RuntimeException ("Fail");
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
        int f = 0;
        while (f < (1 << CBORObject.FLOAT32_SIGNIFICAND_SIZE)) {
            int e = 0;
            while (e < (1 << CBORObject.FLOAT32_EXPONENT_SIZE)) {
                convert((e << CBORObject.FLOAT32_SIGNIFICAND_SIZE) + f);
                e++;
            }
            f++;
        }
        System.out.println("Runs=" + Long.toString(runs));
    }
}

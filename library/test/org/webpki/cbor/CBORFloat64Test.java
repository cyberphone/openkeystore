package org.webpki.cbor;

import static org.webpki.cbor.CBORInternal.FLOAT64_SIGNIFICAND_SIZE;

import java.util.Random;

import org.webpki.util.HexaDecimal;

public class CBORFloat64Test {
    
    static long float64;
    static long float32;
    static long float16;
    static long runs;
    static boolean oneShot;
    
    static void convert (long l) {
        boolean genuine = true;
        boolean simple = true;
        byte[] cbor = null;
        CBORNonFinite nf = null;
        String type = "G";
        try {
            if ((l & CBORInternal.FLOAT64_POS_INFINITY) == CBORInternal.FLOAT64_POS_INFINITY) {
                nf = new CBORNonFinite(l);
                genuine = false;
                simple = nf.isSimple();
                cbor = nf.encode();
                type = simple ? "S" : "X";
            }
            if (simple) {
                cbor = CBORFloat.createExtendedFloat(Double.longBitsToDouble(l)).encode();
            }
            switch (cbor.length) {
                case 3:
                    float16++;
                    break;
                case 5:
                    float32++;
                    break;
                case 9:
                    float64++;
                    break;
                default:
                    throw new RuntimeException("BUG");
            }
            CBORObject object = CBORDecoder.decode(cbor);
            if (simple) {
                double d = Double.longBitsToDouble(l);
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
                if (((nf.getNonFinite64() ^ l) &
                    ((1 << FLOAT64_SIGNIFICAND_SIZE) - 1)) != 0) {
                    throw new RuntimeException ("Fail3");
                }
            }
            if (oneShot || ((++runs % 1000000) == 0)) {
                System.out.println(" 16=" + float16 + 
                                   " 32=" + float32 +
                                   " 64=" + float64 +
                                   " T=" + type +
                                   " E=" + HexaDecimal.encode(cbor));
            }
        } catch (Exception e) {
            System.out.println("**********=" + Long.toUnsignedString(l, 16));
            System.exit(3);
        }
    }
    
    public static void main(String[] argv)  {
        if (argv.length == 0) {
            Random random = new Random();
            while (true) {
                convert(random.nextLong());
            }
        }
        oneShot = true;
        String number = argv[0];
        convert(number.startsWith("x") ?
            Long.parseUnsignedLong(number.substring(1), 16) :
            Double.doubleToLongBits(Double.valueOf(number)));
    }
}

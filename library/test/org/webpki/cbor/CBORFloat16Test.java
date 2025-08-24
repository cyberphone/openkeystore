package org.webpki.cbor;

import java.util.Arrays;

public class CBORFloat16Test {
    
    public static void main(String[] argv)  {
        for (int i = 0; i < 65536; i++) {
            boolean genuine = true;
            boolean simple = true;
            if ((i & 0x7c00) == 0x7c00) {
                // The 5 exponent bits are all set => Special case
                genuine = false;
                switch (i) {
                    case 0x7c00:
                    case 0xfc00:
                    case 0x7e00:
                        break;
                        
                    default:
                        simple = false;
                 }
            }
            byte[] encoded = new byte[] {(byte)0xf9, (byte) (i >> 8), (byte) i};
            try {
                CBORObject cbor = CBORDecoder.decode(encoded);
                if (genuine) {
                    double value = cbor.getFloat64();
                    if (!cbor.equals(new CBORFloat(value))) {
                        throw new RuntimeException("Diff for: " + value);
                    }
                    if (!cbor.equals(new CBORFloat(Double.valueOf(cbor.toString())))) {
                        throw new RuntimeException("Diff2 for: " + value);
                    }
                    System.out.println("VG=" + value + " D=" + org.webpki.util.HexaDecimal.encode(encoded));
                } else {
                    if (simple) {
                        double value = cbor.getExtendedFloat64();
                        if (!Arrays.equals(encoded, cbor.encode())) throw new RuntimeException("en1");
                        if (!Arrays.equals(encoded, CBORFloat.createExtendedFloat(value).encode())) throw new RuntimeException("en2");
                        System.out.println("VS=" + value + " D=" + org.webpki.util.HexaDecimal.encode(encoded));
                    } else {
                        CBORNonFinite nf = (CBORNonFinite) cbor;
                        double value = (double) i;
                        if (i != nf.getNonFinite()) throw new RuntimeException("en3");
                        System.out.println("VN=" + value + " D=" + org.webpki.util.HexaDecimal.encode(encoded));
                    }
                }
            } catch (Exception e) {
                    System.out.println("**********=" + e.getMessage() + " " + org.webpki.util.HexaDecimal.encode(encoded));
                    return;
            }
        }
    }
}

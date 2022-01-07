package org.webpki.cbor;

public class CBORFloat16Test {
    
    public static void main(String[] argv)  {
        for (int i = 0; i < 65536; i++) {
            if ((i & 0x7c00) == 0x7c00) {
                // The 5 exponent bits are all set => Special case
                switch (i) {
                    case CBORDouble.FLOAT16_NOT_A_NUMBER:
                    case CBORDouble.FLOAT16_POS_INFINITY:
                    case CBORDouble.FLOAT16_NEG_INFINITY:
                        break;
                        
                    default:
                        // These values are illegal in deterministic CBOR
                        continue;
                }
            }
            byte[] encoded = new byte[] {(byte)0xf9, (byte) (i >> 8), (byte) i};
            try {
                CBORObject cbor = CBORObject.decode(encoded);
                double value = cbor.getDouble();
                if (!cbor.equals(new CBORDouble(value))) {
                    throw new RuntimeException("Diff for: " + value);
                }
                if (!cbor.equals(new CBORDouble(Double.valueOf(cbor.toString())))) {
                    throw new RuntimeException("Diff2 for: " + value);
                }
                System.out.println("V=" + value + " D=" + org.webpki.util.DebugFormatter.getHexString(encoded));
            } catch (Exception e) {
                System.out.println("**********=" + org.webpki.util.DebugFormatter.getHexString(encoded));
                return;
            }
        }
    }
}

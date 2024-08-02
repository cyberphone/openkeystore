package org.webpki.cbor;

public class CBORFloat16Test {
    
    public static void main(String[] argv)  {
        for (int i = 0; i < 65536; i++) {
            boolean mustFlag = false;
            if ((i & 0x7c00) == 0x7c00) {
                // The 5 exponent bits are all set => Special case
                switch (i) {
                    case 0x7c00:
                    case 0xfc00:
                    case 0x7e00:
                        break;
                        
                    default:
                        // These values are illegal in deterministic CBOR
                        mustFlag = true;
                 }
            }
            byte[] encoded = new byte[] {(byte)0xf9, (byte) (i >> 8), (byte) i};
            try {
                CBORObject cbor = CBORObject.decode(encoded);
                if (mustFlag) {
                    System.out.println("**********=" + org.webpki.util.HexaDecimal.encode(encoded));
                    return;
                }
                double value = cbor.getFloat64();
                if (!cbor.equals(new CBORFloat(value))) {
                    throw new RuntimeException("Diff for: " + value);
                }
                if (!cbor.equals(new CBORFloat(Double.valueOf(cbor.toString())))) {
                    throw new RuntimeException("Diff2 for: " + value);
                }
                System.out.println("V=" + value + " D=" + org.webpki.util.HexaDecimal.encode(encoded));
            } catch (Exception e) {
                if (!mustFlag) {
                    System.out.println("**********=" + org.webpki.util.HexaDecimal.encode(encoded));
                    return;
                }
            }
        }
    }
}


package org.webpki.crypto;

import java.math.BigInteger;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECFieldF2m;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

public class CreateECCurves {
 
    public static void main(String[] argc) {
        try {
            CustomCryptoProvider.forcedLoad(true);
            create("secp256r1");
            create("brainpoolP256r1");
            create("sect233r1");
            create("secp384r1");
            create("secp521r1");
            create("secp256k1");
            System.out.println(publicKeys.toString());
            System.out.println(curves.toString());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    static StringBuilder publicKeys = new StringBuilder();
    
    static StringBuilder curves = new StringBuilder();
    
    static void create(String jceName) throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec(jceName), new SecureRandom());
        KeyPair keyPair = kpg.generateKeyPair();
        ECPublicKey generatedEcPublicKey = (ECPublicKey) keyPair.getPublic();
        ECPoint ecPoint = generatedEcPublicKey.getW();
        ECParameterSpec generatedSpec = generatedEcPublicKey.getParams();
        globalIndent = 8;
        publicKeys.append("\n    createSamplePublicKey(\"" + jceName + "\",\n")
                  .append(byteList(ecPoint.getAffineX()))
                  .append(",\n")
                  .append(byteList(ecPoint.getAffineY()))
                  .append(",\n")
                  .append(byteList(generatedEcPublicKey.getEncoded()))
                  .append(");\n");
        position = 0;
        globalIndent = 16;
        EllipticCurve curve = generatedSpec.getCurve();
        ECPoint generator = generatedSpec.getGenerator();
        curves.append("\n\"")
              .append(jceName)
              .append("\"\n")
              .append(space(globalIndent - 4))
              .append("createECParameterSpec(\n")
              .append(space(globalIndent))
              .append(curve.getField() instanceof ECFieldFp)
              .append(",\n")
              .append(byteList(curve.getField() instanceof ECFieldFp ? 
                      ((ECFieldFp)curve.getField()).getP()
                                      :
                      ((ECFieldF2m)curve.getField()).getReductionPolynomial()))
              .append(",\n")
              .append(byteList(curve.getA()))
              .append(",\n")
              .append(byteList(curve.getB()))
              .append(",\n")
              .append(byteList(generator.getAffineX()))
              .append(",\n")
              .append(byteList(generator.getAffineY()))
              .append(",\n")
              .append(byteList(generatedSpec.getOrder()))
              .append(",\n")
              .append(space(globalIndent))
              .append(generatedSpec.getCofactor())
              .append(");\n");
    }
    
    static int globalIndent = 4;
    
    static int position = 0;
    
    static final int MAX_POSITION = 97;
    
    static StringBuilder byteList(BigInteger value) {
        return byteList(value.toByteArray());
    }
    
    static StringBuilder byteList(byte[] bytes) {
        StringBuilder list = new StringBuilder();
        list.append(space(globalIndent))
            .append("new byte[]\n");
        position = 0;
            list.append(space(globalIndent + 3))
                .append("{")
                .append(bytePrint(bytes[0]));
        position += 11;
        for (int q = 1; q < bytes.length; q++) {
            if (position + 12 > MAX_POSITION) {
                position = 0;
                list.append(",\n")
                    .append(space(globalIndent + 4));
            } else {
                position += 2;
                list.append(", ");
            }
            list.append(bytePrint(bytes[q]));
            position += 10;
        }
        return list.append("}");
    }

    private static String bytePrint(byte b) {
        return String.format("(byte)0x%02x", b & 0xff);
    }

    static StringBuilder space(int indent) {
        StringBuilder spaces = new StringBuilder();
        for (int q = 0; q < indent; q++) {
            spaces.append(' ');
        }
        position = indent;
        return spaces;
    }
}

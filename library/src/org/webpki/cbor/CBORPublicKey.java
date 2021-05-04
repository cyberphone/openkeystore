/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import java.io.IOException;

import java.math.BigInteger;

import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;

import java.util.HashMap;

import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.OkpSupport;

import org.webpki.util.ArrayUtil;

/**
 * Class for CBOR/COSE public keys
 * 
 */
public class CBORPublicKey {
    
    ////////////////////////////////
    // From RFC 8152 and RFC 8230 //
    ////////////////////////////////
    static final int KTY     = 1;
    
    static final int OKP_KTY_ARGUMENT = 1;
    static final int OKP_CRV  = -1;
    static final int OKP_X    = -2;
     
    static final int EC2_KTY_ARGUMENT = 2;
    static final int EC2_CRV  = -1;
    static final int EC2_X    = -2;
    static final int EC2_Y    = -3;
    
    static final int RSA_KTY_ARGUMENT = 3;
    static final int RSA_N   = -1;
    static final int RSA_E   = -2;

    static CBORInteger OKP_CBOR_KTY = new CBORInteger(OKP_KTY_ARGUMENT);
    static CBORInteger EC2_CBOR_KTY = new CBORInteger(EC2_KTY_ARGUMENT);
    static CBORInteger RSA_CBOR_KTY = new CBORInteger(RSA_KTY_ARGUMENT);
    
    static final HashMap<KeyAlgorithms, CBORInteger> COSE_CRV = new HashMap<>();

    static {
        COSE_CRV.put(KeyAlgorithms.NIST_P_256, new CBORInteger(1));
        COSE_CRV.put(KeyAlgorithms.NIST_P_384, new CBORInteger(2));
        COSE_CRV.put(KeyAlgorithms.NIST_P_521, new CBORInteger(3));
        COSE_CRV.put(KeyAlgorithms.X25519,     new CBORInteger(4));
        COSE_CRV.put(KeyAlgorithms.X448,       new CBORInteger(5));
        COSE_CRV.put(KeyAlgorithms.ED25519,    new CBORInteger(6));
        COSE_CRV.put(KeyAlgorithms.ED448,      new CBORInteger(7));
    }

    static CBORByteString cryptoBinary(BigInteger value) {
        byte[] cryptoBinary = value.toByteArray();
        if (cryptoBinary[0] == 0x00) {
            byte[] woZero = new byte[cryptoBinary.length - 1];
            System.arraycopy(cryptoBinary, 1, woZero, 0, woZero.length);
            cryptoBinary = woZero;
        }
        return new CBORByteString(cryptoBinary);        
    }

    static CBORByteString curvePoint(BigInteger value, KeyAlgorithms ec) throws IOException {
        byte[] curvePoint = value.toByteArray();
        if (curvePoint.length > (ec.getPublicKeySizeInBits() + 7) / 8) {
            if (curvePoint[0] != 0) {
                throw new IOException("Unexpected EC point");
            }
            return cryptoBinary(value);
        }
        while (curvePoint.length < (ec.getPublicKeySizeInBits() + 7) / 8) {
            curvePoint = ArrayUtil.add(new byte[]{0}, curvePoint);
        }
        return new CBORByteString(curvePoint);        
     }

    public static CBORIntegerMap createPublicKey(PublicKey publicKey) throws IOException {
        CBORIntegerMap cborPublicKey = new CBORIntegerMap();
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(publicKey);
        switch (keyAlg.getKeyType()) {
        case RSA:
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            cborPublicKey.setMappedValue(KTY, RSA_CBOR_KTY)
                         .setMappedValue(RSA_N, cryptoBinary(rsaPublicKey.getModulus()))
                         .setMappedValue(RSA_E, cryptoBinary(rsaPublicKey.getPublicExponent()));
            break;

        case EC:
            ECPoint ecPoint = ((ECPublicKey) publicKey).getW();
            cborPublicKey.setMappedValue(KTY, EC2_CBOR_KTY)
                         .setMappedValue(EC2_CRV, COSE_CRV.get(keyAlg))
                         .setMappedValue(EC2_X, curvePoint(ecPoint.getAffineX(), keyAlg))
                         .setMappedValue(EC2_Y, curvePoint(ecPoint.getAffineY(), keyAlg));
            break;
 
        default:  // EDDSA and XEC
            cborPublicKey.setMappedValue(KTY, OKP_CBOR_KTY)
                         .setMappedValue(OKP_CRV, COSE_CRV.get(keyAlg))
                         .setMappedValue(OKP_X, new CBORByteString(
                                 OkpSupport.public2RawOkpKey(publicKey, keyAlg)));
        }
        return cborPublicKey;
    }
}

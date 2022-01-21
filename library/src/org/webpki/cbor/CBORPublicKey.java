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

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PublicKey;

import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.HashMap;

import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyTypes;
import org.webpki.crypto.OkpSupport;

import org.webpki.util.ArrayUtil;

/**
 * Class for CBOR/COSE public keys
 * 
 */
public class CBORPublicKey {
    
    private CBORPublicKey() {}
    
    ////////////////////////////////
    // From RFC 8152 and RFC 8230 //
    ////////////////////////////////
    static final int KTY          = 1;
    
    static final int OKP_KTY      = 1;
    static final int OKP_CRV      = -1;
    static final int OKP_X        = -2;
     
    static final int EC2_KTY      = 2;
    static final int EC2_CRV      = -1;
    static final int EC2_X        = -2;
    static final int EC2_Y        = -3;
    
    static final int RSA_KTY      = 3;
    static final int RSA_N        = -1;
    static final int RSA_E        = -2;

    static final HashMap<KeyAlgorithms, Integer> WEBPKI_2_COSE_CRV = new HashMap<>();

    static {
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.NIST_P_256, 1);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.NIST_P_384, 2);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.NIST_P_521, 3);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.X25519,     4);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.X448,       5);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.ED25519,    6);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.ED448,      7);
    }

    static final HashMap<Integer, KeyAlgorithms> COSE_2_WEBPKI_CRV = new HashMap<>();
    
    static {
        for (KeyAlgorithms key : WEBPKI_2_COSE_CRV.keySet()) {
            COSE_2_WEBPKI_CRV.put(WEBPKI_2_COSE_CRV.get(key), key);
        }
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

    static CBORByteString curvePoint(BigInteger value, 
                                     KeyAlgorithms ec) throws GeneralSecurityException {
        byte[] curvePoint = value.toByteArray();
        if (curvePoint.length > (ec.getPublicKeySizeInBits() + 7) / 8) {
            if (curvePoint[0] != 0) {
                throw new GeneralSecurityException("Unexpected EC point");
            }
            return cryptoBinary(value);
        }
        while (curvePoint.length < (ec.getPublicKeySizeInBits() + 7) / 8) {
            curvePoint = ArrayUtil.add(new byte[]{0}, curvePoint);
        }
        return new CBORByteString(curvePoint);        
    }

    /**
     * Java/JCE to CBOR/COSE conversion.
     * 
     * @param publicKey
     * @return Public key in CBOR format
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static CBORMap encode(PublicKey publicKey) 
            throws IOException, GeneralSecurityException {
        CBORMap cborPublicKey = new CBORMap();
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(publicKey);
        switch (keyAlg.getKeyType()) {
        case RSA:
            RSAPublicKey rsaPublicKey = (RSAPublicKey) publicKey;
            cborPublicKey.setObject(KTY, new CBORInteger(RSA_KTY))
                         .setObject(RSA_N, cryptoBinary(rsaPublicKey.getModulus()))
                         .setObject(RSA_E, cryptoBinary(rsaPublicKey.getPublicExponent()));
            break;

        case EC:
            ECPoint ecPoint = ((ECPublicKey) publicKey).getW();
            cborPublicKey.setObject(KTY, new CBORInteger(EC2_KTY))
                         .setObject(EC2_CRV, new CBORInteger(WEBPKI_2_COSE_CRV.get(keyAlg)))
                         .setObject(EC2_X, curvePoint(ecPoint.getAffineX(), keyAlg))
                         .setObject(EC2_Y, curvePoint(ecPoint.getAffineY(), keyAlg));
            break;
 
        default:  // EDDSA and XEC
            cborPublicKey.setObject(KTY, new CBORInteger(OKP_KTY))
                         .setObject(OKP_CRV, new CBORInteger(WEBPKI_2_COSE_CRV.get(keyAlg)))
                         .setObject(OKP_X, new CBORByteString(
                                 OkpSupport.public2RawOkpKey(publicKey, keyAlg)));
        }
        return cborPublicKey;
    }

    static BigInteger getCryptoBinary(CBORObject value) 
            throws IOException, GeneralSecurityException {
        byte[] cryptoBinary = value.getByteString();
        if (cryptoBinary[0] == 0x00) {
            throw new GeneralSecurityException("RSA key parameter contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    static BigInteger getCurvePoint(CBORObject value, KeyAlgorithms ec) 
            throws IOException, GeneralSecurityException {
        byte[] fixedBinary = value.getByteString();
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new GeneralSecurityException("Public EC key parameter is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    /**
     * CBOR/COSE to Java/JCE conversion.
     * 
     * @param cborPublicKey Public key in CBOR format
     * @return Public key as a Java object 
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey decode(CBORObject cborPublicKey) 
    throws IOException, GeneralSecurityException {
        CBORMap publicKeyMap = cborPublicKey.getMap();
        KeyAlgorithms keyAlgorithm;
        int kty = publicKeyMap.getObject(KTY).getInt();
        PublicKey publicKey;

        if (kty == RSA_KTY) {
            publicKey =  KeyFactory.getInstance("RSA").generatePublic(
                    new RSAPublicKeySpec(getCryptoBinary(publicKeyMap.getObject(RSA_N)),
                                         getCryptoBinary(publicKeyMap.getObject(RSA_E))));

        } else if (kty == EC2_KTY) {
            keyAlgorithm = COSE_2_WEBPKI_CRV.get(publicKeyMap.getObject(EC2_CRV).getInt());
            if (keyAlgorithm.getKeyType() != KeyTypes.EC) {
                throw new GeneralSecurityException(keyAlgorithm.getKeyType()  +
                                                   " is not a valid EC curve");
            }
            publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                new ECPoint(getCurvePoint(publicKeyMap.getObject(EC2_X), keyAlgorithm),
                            getCurvePoint(publicKeyMap.getObject(EC2_Y), keyAlgorithm)),
                keyAlgorithm.getECParameterSpec()));

        } else if (kty == OKP_KTY) {
            keyAlgorithm = COSE_2_WEBPKI_CRV.get(publicKeyMap.getObject(OKP_CRV).getInt());
            if (keyAlgorithm.getKeyType() != KeyTypes.EDDSA &&
                keyAlgorithm.getKeyType() != KeyTypes.XEC) {
                throw new GeneralSecurityException(keyAlgorithm.getKeyType()  +
                                                   " is not a valid OKP curve");
            }
            publicKey = OkpSupport.raw2PublicOkpKey(publicKeyMap.getObject(OKP_X).getByteString(), 
                                                    keyAlgorithm);
        } else {
            throw new GeneralSecurityException("Unrecognized key type: " + kty);
        }
        publicKeyMap.checkForUnread();
        return publicKey;
    }
}

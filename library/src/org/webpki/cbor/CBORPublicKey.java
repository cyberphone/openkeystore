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

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class handling CBOR/COSE public keys.
 * <p>
 * See {@link CBORKeyPair}.
 * </p>
 */
public class CBORPublicKey {
    
    private CBORPublicKey() {}
    
    static final HashMap<KeyAlgorithms, CBORObject> WEBPKI_2_COSE_CRV = new HashMap<>();

    static {
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.P_256,   COSE_CRV_P_256);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.P_384,   COSE_CRV_P_384);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.P_521,   COSE_CRV_P_521);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.X25519,  COSE_CRV_X25519);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.X448,    COSE_CRV_X448);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.ED25519, COSE_CRV_ED25519);
        WEBPKI_2_COSE_CRV.put(KeyAlgorithms.ED448,   COSE_CRV_ED448);
    }
    
    static final HashMap<Integer, KeyAlgorithms> COSE_2_WEBPKI_CRV = new HashMap<>();
    
    static {
        for (KeyAlgorithms key : WEBPKI_2_COSE_CRV.keySet()) {
            try {
                COSE_2_WEBPKI_CRV.put(WEBPKI_2_COSE_CRV.get(key).getInt(), key);
            } catch (IOException e) {
            }
        }
    }
    
    static final HashMap<Integer,KeyTypes> keyTypes = new HashMap<>();
    
    static {
        try {
            keyTypes.put(COSE_RSA_KTY.getInt(), KeyTypes.RSA);
            keyTypes.put(COSE_EC2_KTY.getInt(), KeyTypes.EC);
            keyTypes.put(COSE_OKP_KTY.getInt(), KeyTypes.EDDSA); // XEC and EDDSA share kty...
        } catch (IOException e) {
        }
    }

    static byte[] cryptoBinary(BigInteger value) {
        byte[] cryptoBinary = value.toByteArray();
        if (cryptoBinary[0] == 0x00) {
            byte[] woZero = new byte[cryptoBinary.length - 1];
            System.arraycopy(cryptoBinary, 1, woZero, 0, woZero.length);
            return woZero;
        }
        return cryptoBinary;        
    }

    static byte[] curvePoint(BigInteger value, KeyAlgorithms ec) throws GeneralSecurityException {
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
        return curvePoint;        
    }
    
     /**
     * Converts JCE public key to COSE.
     * 
     * @param jcePublicKey Public key in Java/JCE format
     * @return Public key in COSE format
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static CBORMap convert(PublicKey jcePublicKey) 
            throws IOException, GeneralSecurityException {
        CBORMap cosePublicKey = new CBORMap();
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(jcePublicKey);
        switch (keyAlg.getKeyType()) {
            case RSA:
                RSAPublicKey rsaPublicKey = (RSAPublicKey) jcePublicKey;
                cosePublicKey.setObject(COSE_KTY_LABEL, COSE_RSA_KTY)
                             .setBytes(COSE_RSA_N_LABEL,
                                       cryptoBinary(rsaPublicKey.getModulus()))
                             .setBytes(COSE_RSA_E_LABEL, 
                                       cryptoBinary(rsaPublicKey.getPublicExponent()));
                break;
    
            case EC:
                ECPoint ecPoint = ((ECPublicKey) jcePublicKey).getW();
                cosePublicKey.setObject(COSE_KTY_LABEL, COSE_EC2_KTY)
                             .setObject(COSE_EC2_CRV_LABEL, WEBPKI_2_COSE_CRV.get(keyAlg))
                             .setBytes(COSE_EC2_X_LABEL, curvePoint(ecPoint.getAffineX(), keyAlg))
                             .setBytes(COSE_EC2_Y_LABEL, curvePoint(ecPoint.getAffineY(), keyAlg));
                break;
     
            default:  // EDDSA and XEC
                cosePublicKey.setObject(COSE_KTY_LABEL, COSE_OKP_KTY)
                             .setObject(COSE_OKP_CRV_LABEL, WEBPKI_2_COSE_CRV.get(keyAlg))
                             .setBytes(COSE_OKP_X_LABEL,
                                       OkpSupport.public2RawKey(jcePublicKey, keyAlg));
        }
        return cosePublicKey;
    }

    static BigInteger getCryptoBinary(CBORMap keyMap, CBORObject key) 
            throws IOException, GeneralSecurityException {
        byte[] cryptoBinary = keyMap.getObject(key).getBytes();
        if (cryptoBinary[0] == 0x00) {
            throw new GeneralSecurityException("RSA key parameter contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    static BigInteger getCurvePoint(CBORMap keyMap, CBORObject key, KeyAlgorithms ec) 
            throws IOException, GeneralSecurityException {
        byte[] fixedBinary = keyMap.getObject(key).getBytes();
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new GeneralSecurityException("Public EC key parameter is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    static KeyAlgorithms getKeyAlgorithmFromCurveId(CBORMap keyMap, CBORObject curveLabel)
                throws IOException, GeneralSecurityException {
        CBORObject curve = keyMap.getObject(curveLabel);
        KeyAlgorithms keyAlgorithm = COSE_2_WEBPKI_CRV.get(curve.getInt());
        if (keyAlgorithm == null) {
            throw new GeneralSecurityException("No such key/curve algorithm: " + curve.getInt());
        }
        return keyAlgorithm;
    }
    
    static KeyTypes getKeyType(CBORMap coseKeyMap) throws IOException, GeneralSecurityException {
        int coseKty = coseKeyMap.getObject(COSE_KTY_LABEL).getInt();
        KeyTypes keyType = keyTypes.get(coseKty);
        if (keyType == null) {
            throw new GeneralSecurityException("Unrecognized key type: " + coseKty);
        }
        return keyType;
    }
    
    static PublicKey getPublicKey(CBORMap publicKeyMap) 
            throws IOException, GeneralSecurityException {
        KeyAlgorithms keyAlg;
        PublicKey publicKey;
        switch (getKeyType(publicKeyMap)) {
            case RSA:
                publicKey = KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(
                    getCryptoBinary(publicKeyMap, COSE_RSA_N_LABEL),
                    getCryptoBinary(publicKeyMap, COSE_RSA_E_LABEL)));
                break;
    
            case EC:
                keyAlg = getKeyAlgorithmFromCurveId(publicKeyMap, COSE_EC2_CRV_LABEL);
                if (keyAlg.getKeyType() != KeyTypes.EC) {
                    throw new GeneralSecurityException("Invalid EC curve: " + keyAlg.toString());
                }
                publicKey = KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(
                    new ECPoint(getCurvePoint(publicKeyMap, COSE_EC2_X_LABEL, keyAlg),
                                getCurvePoint(publicKeyMap, COSE_EC2_Y_LABEL, keyAlg)),
                    keyAlg.getECParameterSpec()));
                break;
    
            default:  // EDDSA and XEC
                keyAlg = getKeyAlgorithmFromCurveId(publicKeyMap, COSE_OKP_CRV_LABEL);
                if (keyAlg.getKeyType() != KeyTypes.EDDSA && keyAlg.getKeyType() != KeyTypes.XEC) {
                    throw new GeneralSecurityException("Invalid OKP curve: " + keyAlg.toString());
                }
                publicKey = OkpSupport.raw2PublicKey(
                    publicKeyMap.getObject(COSE_OKP_X_LABEL).getBytes(), keyAlg);
        }
        return publicKey;
    }

    /**
     * Converts COSE public key to JCE.
     * 
     * @param cosePublicKey Public key in COSE format
     * @return Public key as a Java/JCE object 
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static PublicKey convert(CBORObject cosePublicKey) 
            throws IOException, GeneralSecurityException {
        CBORMap publicKeyMap = cosePublicKey.getMap();
        PublicKey publicKey = getPublicKey(publicKeyMap);
        publicKeyMap.checkForUnread();
        return publicKey;
    }
}

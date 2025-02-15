/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.cbor;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPrivateKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;

import org.webpki.crypto.CryptoException;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.OkpSupport;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class handling Java/COSE private key conversions.
 * <p>
 * See also {@link CBORPublicKey}.
 * </p>
 * <p>
 * Note: this implementation does not support RSA multiprime keys.
 * </p>
 */
public class CBORKeyPair {
    
    private CBORKeyPair() {}
    
    static final CBORInt COSE_EC2_D_LBL        = new CBORInt(-4);
    static final CBORInt COSE_OKP_D_LBL        = new CBORInt(-4);

    /*
            https://datatracker.ietf.org/doc/html/rfc8230
        +-------+-------+-------+-------+-----------------------------------+
        | Key   | Name  | Label | CBOR  | Description                       |
        | Type  |       |       | Type  |                                   |
        +-------+-------+-------+-------+-----------------------------------+
        | 3     | n     | -1    | bstr  | the RSA modulus n                 |
        | 3     | e     | -2    | bstr  | the RSA public exponent e         |
        | 3     | d     | -3    | bstr  | the RSA private exponent d        |
        | 3     | p     | -4    | bstr  | the prime factor p of n           |
        | 3     | q     | -5    | bstr  | the prime factor q of n           |
        | 3     | dP    | -6    | bstr  | dP is d mod (p - 1)               |
        | 3     | dQ    | -7    | bstr  | dQ is d mod (q - 1)               |
        | 3     | qInv  | -8    | bstr  | qInv is the CRT coefficient       |

                               UNSUPPORTED
        
        |       |       |       |       | q^(-1) mod p                      |
        | 3     | other | -9    | array | other prime infos, an array       |
        | 3     | r_i   | -10   | bstr  | a prime factor r_i of n, where i  |
        |       |       |       |       | >= 3                              |
        | 3     | d_i   | -11   | bstr  | d_i = d mod (r_i - 1)             |
        | 3     | t_i   | -12   | bstr  | the CRT coefficient t_i = (r_1 *  |
        |       |       |       |       | r_2 * ... * r_(i-1))^(-1) mod r_i |
        +-------+-------+-------+-------+-----------------------------------+
    */

    static final CBORInt COSE_RSA_D_LBL        = new CBORInt(-3);
    static final CBORInt COSE_RSA_P_LBL        = new CBORInt(-4);
    static final CBORInt COSE_RSA_Q_LBL        = new CBORInt(-5);
    static final CBORInt COSE_RSA_DP_LBL       = new CBORInt(-6);
    static final CBORInt COSE_RSA_DQ_LBL       = new CBORInt(-7);
    static final CBORInt COSE_RSA_QINV_LBL     = new CBORInt(-8);

    /**
     * Convert JCE key pair to COSE.
     * 
     * @param keyPair in Java/JCE format
     * @return Private key in COSE format
     * @throws CryptoException
    */
    public static CBORMap convert(KeyPair keyPair) {
        CBORMap cosePrivateKey = CBORPublicKey.convert(keyPair.getPublic());
        KeyAlgorithms keyAlg = KeyAlgorithms.getKeyAlgorithm(keyPair.getPublic());
        switch (keyAlg.getKeyType()) {
            case RSA:
                RSAPrivateCrtKey rsaPrivateKey = (RSAPrivateCrtKey)keyPair.getPrivate();
                cosePrivateKey
                    .set(COSE_RSA_D_LBL, 
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getPrivateExponent()))
                    .set(COSE_RSA_P_LBL, 
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getPrimeP()))
                    .set(COSE_RSA_Q_LBL, 
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getPrimeQ()))
                    .set(COSE_RSA_DP_LBL, 
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getPrimeExponentP()))
                    .set(COSE_RSA_DQ_LBL, 
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getPrimeExponentQ()))
                    .set(COSE_RSA_QINV_LBL,
                         CBORPublicKey.cryptoBinary(rsaPrivateKey.getCrtCoefficient()));
                break;

            case EC:
                cosePrivateKey.set(COSE_EC2_D_LBL,
                        CBORPublicKey.curvePoint(((ECPrivateKey)keyPair.getPrivate()).getS(), 
                                                 keyAlg));
                break;

            default:
                cosePrivateKey.set(COSE_OKP_D_LBL, new CBORBytes(
                        OkpSupport.private2RawKey(keyPair.getPrivate(), keyAlg)));
            
        }
        return cosePrivateKey;
    }

    /**
     * Convert COSE private key to JCE.
     * <p>
     * Note: there <b>must not</b> be any additional items like key identifiers
     * or mandated signature algorithms.
     * </p>
     * @param cosePrivateKey Private key in COSE format
     * @return KeyPair as a Java/JCE object
     * @throws CryptoException
     * @throws CBORException 
     */
    public static KeyPair convert(CBORObject cosePrivateKey) {
        CBORMap privateKeyMap = cosePrivateKey.getMap();
        PublicKey publicKey = CBORPublicKey.getPublicKey(privateKeyMap);
        PrivateKey privateKey;
        try {
            switch (CBORPublicKey.getKeyType(privateKeyMap)) {
                case RSA:
                    privateKey = KeyFactory.getInstance("RSA").generatePrivate(
                        new RSAPrivateCrtKeySpec(
                            ((RSAPublicKey) publicKey).getModulus(),
                            ((RSAPublicKey) publicKey).getPublicExponent(),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_D_LBL),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_P_LBL),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_Q_LBL),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_DP_LBL),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_DQ_LBL),
                            CBORPublicKey.getCryptoBinary(privateKeyMap, COSE_RSA_QINV_LBL)));
                    break;
    
                case EC:
                    privateKey = KeyFactory.getInstance("EC").generatePrivate(new ECPrivateKeySpec(
                            CBORPublicKey.getCurvePoint(privateKeyMap,
                                                        COSE_EC2_D_LBL, 
                                                        CBORPublicKey.getKeyAlgorithmFromCurveId(
                                                                        privateKeyMap,
                                                                        COSE_EC2_CRV_LBL)),
                            ((ECKey)publicKey).getParams()));
                    break;
    
                default:
                    privateKey = OkpSupport.raw2PrivateKey(
                            privateKeyMap.get(COSE_OKP_D_LBL).getBytes(),
                            CBORPublicKey.getKeyAlgorithmFromCurveId(privateKeyMap, 
                                                                     COSE_OKP_CRV_LBL));
            }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
        privateKeyMap.checkForUnread();
        return new KeyPair(publicKey, privateKey);
    }
}

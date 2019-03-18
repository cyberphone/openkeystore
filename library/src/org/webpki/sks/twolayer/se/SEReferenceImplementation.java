/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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
package org.webpki.sks.twolayer.se;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.Serializable;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyPair;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.LinkedHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.sks.DeviceInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;

/*
 *                          ################################################
 *                          #  SKS - Secure Key Store - Two Layer Version  #
 *                          #          SE - Security Element Part          #
 *                          ################################################
 *
 *  SKS is a cryptographic module that supports On-line Provisioning and Management
 *  of PKI, Symmetric keys, PINs, PUKs and Extension data.
 *
 *  Author: Anders Rundgren
 */
public class SEReferenceImplementation {

    /////////////////////////////////////////////////////////////////////////////////////////////
    // SKS version and configuration data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final String SKS_VENDOR_NAME           = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION    = "SKS TEE/SE RI - SE Module";
    static final String SKS_UPDATE_URL            = null;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT = true;  // Change here to test or disable
    static final int MAX_LENGTH_CRYPTO_DATA       = 16384;
    static final int MAX_LENGTH_EXTENSION_DATA    = 65536;

    static final char[] BASE64_URL = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                      'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                      'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                      'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                      'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                      'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                      'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                      '4', '5', '6', '7', '8', '9', '-', '_'};

    static class SignatureWrapper {

        static final int ASN1_SEQUENCE = 0x30;
        static final int ASN1_INTEGER  = 0x02;

        static final int LEADING_ZERO  = 0x00;

        Signature instance;
        boolean rsaFlag;
        int extendTo;

        public SignatureWrapper(String algorithm, PublicKey publicKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initVerify(publicKey);
            rsaFlag = publicKey instanceof RSAPublicKey;
            if (!rsaFlag) {
                extendTo = getEcPointLength((ECKey) publicKey);
            }
        }

        public SignatureWrapper(String algorithm, PrivateKey privateKey) throws GeneralSecurityException {
            instance = Signature.getInstance(algorithm);
            instance.initSign(privateKey);
            rsaFlag = privateKey instanceof RSAPrivateKey;
            if (!rsaFlag) {
                extendTo = getEcPointLength((ECKey) privateKey);
            }
        }

        public SignatureWrapper update(byte[] data) throws GeneralSecurityException {
            instance.update(data);
            return this;
        }

        public SignatureWrapper update(byte data) throws GeneralSecurityException {
            instance.update(data);
            return this;
        }

        public boolean verify(byte[] signature) throws GeneralSecurityException {
            if (rsaFlag) {
                return instance.verify(signature);
            }
            if (extendTo != signature.length / 2) {
                throw new GeneralSecurityException("Signature length error");
            }

            int i = extendTo;
            while (i > 0 && signature[extendTo - i] == LEADING_ZERO) {
                i--;
            }
            int j = i;
            if (signature[extendTo - i] < 0) {
                j++;
            }

            int k = extendTo;
            while (k > 0 && signature[2 * extendTo - k] == LEADING_ZERO) {
                k--;
            }
            int l = k;
            if (signature[2 * extendTo - k] < 0) {
                l++;
            }

            int len = 2 + j + 2 + l;
            int offset = 1;
            byte derCodedSignature[];
            if (len < 128) {
                derCodedSignature = new byte[len + 2];
            } else {
                derCodedSignature = new byte[len + 3];
                derCodedSignature[1] = (byte) 0x81;
                offset = 2;
            }
            derCodedSignature[0] = ASN1_SEQUENCE;
            derCodedSignature[offset++] = (byte) len;
            derCodedSignature[offset++] = ASN1_INTEGER;
            derCodedSignature[offset++] = (byte) j;
            System.arraycopy(signature, extendTo - i, derCodedSignature, offset + j - i, i);
            offset += j;
            derCodedSignature[offset++] = ASN1_INTEGER;
            derCodedSignature[offset++] = (byte) l;
            System.arraycopy(signature, 2 * extendTo - k, derCodedSignature, offset + l - k, k);
            return instance.verify(derCodedSignature);
        }

        byte[] sign() throws GeneralSecurityException {
            byte[] signature = instance.sign();
            if (rsaFlag) {
                return signature;
            }
            int index = 2;
            byte[] integerPairs = new byte[extendTo << 1];
            if (signature[0] != ASN1_SEQUENCE) {
                throw new GeneralSecurityException("Not SEQUENCE");
            }
            int length = signature[1];
            if (length < 4) {
                if (length != -127) {
                    throw new GeneralSecurityException("Bad ASN.1 length");
                }
                length = signature[index++] & 0xFF;
            }
            for (int offset = 0; offset <= extendTo; offset += extendTo) {
                if (signature[index++] != ASN1_INTEGER) {
                    throw new GeneralSecurityException("Not INTEGER");
                }
                int l = signature[index++];
                while (l > extendTo) {
                    if (signature[index++] != LEADING_ZERO) {
                        throw new GeneralSecurityException("Bad INTEGER");
                    }
                    l--;
                }
                System.arraycopy(signature, index, integerPairs, offset + extendTo - l, l);
                index += l;
            }
            if (index != signature.length) {
                throw new GeneralSecurityException("ASN.1 Length error");
            }
            return integerPairs;
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Algorithm Support
    /////////////////////////////////////////////////////////////////////////////////////////////

    static class Algorithm implements Serializable {
        private static final long serialVersionUID = 1L;

        int mask;
        String jceName;
        byte[] pkcs1DigestInfo;
        ECParameterSpec ecParameterSpec;
        int ecPointLength;

        void addEcCurve(int ecPointLength, byte[] samplePublicKey) {
            this.ecPointLength = ecPointLength;
            try {
                ecParameterSpec = ((ECPublicKey) KeyFactory.getInstance("EC")
                    .generatePublic(new X509EncodedKeySpec(samplePublicKey))).getParams();
            } catch (Exception e) {
                new RuntimeException(e);
            }
        }
    }

    static LinkedHashMap<String, Algorithm> supportedAlgorithms = new LinkedHashMap<String, Algorithm>();

    static Algorithm addAlgorithm(String uri, String jceName, int mask) {
        Algorithm alg = new Algorithm();
        alg.mask = mask;
        alg.jceName = jceName;
        supportedAlgorithms.put(uri, alg);
        return alg;
    }

    static final int ALG_SYM_ENC  = 0x00000001;
    static final int ALG_IV_REQ   = 0x00000002;
    static final int ALG_IV_INT   = 0x00000004;
    static final int ALG_SYML_128 = 0x00000008;
    static final int ALG_SYML_192 = 0x00000010;
    static final int ALG_SYML_256 = 0x00000020;
    static final int ALG_HMAC     = 0x00000040;
    static final int ALG_ASYM_ENC = 0x00000080;
    static final int ALG_ASYM_SGN = 0x00000100;
    static final int ALG_RSA_KEY  = 0x00004000;
    static final int ALG_RSA_GMSK = 0x00003FFF;
    static final int ALG_RSA_EXP  = 0x00008000;
    static final int ALG_HASH_256 = 0x00200000;
    static final int ALG_HASH_384 = 0x00300000;
    static final int ALG_HASH_512 = 0x00400000;
    static final int ALG_HASH_DIV = 0x00010000;
    static final int ALG_HASH_MSK = 0x0000007F;
    static final int ALG_NONE     = 0x00800000;
    static final int ALG_ASYM_KA  = 0x01000000;
    static final int ALG_AES_PAD  = 0x02000000;
    static final int ALG_EC_KEY   = 0x04000000;
    static final int ALG_KEY_GEN  = 0x08000000;
    static final int ALG_KEY_PARM = 0x10000000;

    static {
        //////////////////////////////////////////////////////////////////////////////////////
        //  Symmetric Key Encryption and Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes128-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_128);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes192-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_192);

        addAlgorithm("http://www.w3.org/2001/04/xmlenc#aes256-cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_INT | ALG_IV_REQ | ALG_SYML_256);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#aes.ecb.nopad",
                     "AES/ECB/NoPadding",
                     ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 | ALG_AES_PAD);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#aes.cbc",
                     "AES/CBC/PKCS5Padding",
                     ALG_SYM_ENC | ALG_IV_REQ | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  HMAC Operations
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2000/09/xmldsig#hmac-sha1", "HmacSHA1", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha256", "HmacSHA256", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha384", "HmacSHA384", ALG_HMAC);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#hmac-sha512", "HmacSHA512", ALG_HMAC);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Decryption
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.es.pkcs1_5",
                     "RSA/ECB/PKCS1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha1.mgf1p",
                     "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.oaep.sha256.mgf1p",
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.raw",
                     "RSA/ECB/NoPadding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ecdh.raw",
                     "ECDH",
                     ALG_ASYM_KA | ALG_EC_KEY);
        
        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Signatures
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_256).pkcs1DigestInfo =
                         new byte[]{0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha384",
                     "NONEwithRSA",
                      ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_384).pkcs1DigestInfo =
                          new byte[]{0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                     0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY | ALG_HASH_512).pkcs1DigestInfo =
                         new byte[]{0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte)0x86, 0x48,
                                    0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40};

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_256);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha384",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_384);

        addAlgorithm("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha512",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY | ALG_HASH_512);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa.pkcs1.none",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ecdsa.none",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Generation
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p256",
                     "secp256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (32, new byte[]
              {(byte)0x30, (byte)0x59, (byte)0x30, (byte)0x13, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x08, (byte)0x2A,
               (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x03, (byte)0x01, (byte)0x07, (byte)0x03,
               (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x8B, (byte)0xDF, (byte)0x5D, (byte)0xA2, (byte)0xBE,
               (byte)0x57, (byte)0x73, (byte)0xAC, (byte)0x78, (byte)0x86, (byte)0xD3, (byte)0xE5, (byte)0xE6,
               (byte)0xC4, (byte)0xA5, (byte)0x6C, (byte)0x32, (byte)0xE2, (byte)0x28, (byte)0xBE, (byte)0xA0,
               (byte)0x0F, (byte)0x8F, (byte)0xBF, (byte)0x29, (byte)0x1E, (byte)0xC6, (byte)0x67, (byte)0xB3,
               (byte)0x51, (byte)0x99, (byte)0xB7, (byte)0xAD, (byte)0x13, (byte)0x0C, (byte)0x5A, (byte)0x7C,
               (byte)0x66, (byte)0x4B, (byte)0x47, (byte)0xF6, (byte)0x1F, (byte)0x41, (byte)0xE9, (byte)0xB3,
               (byte)0xB2, (byte)0x40, (byte)0xC0, (byte)0x65, (byte)0xF8, (byte)0x8F, (byte)0x30, (byte)0x0A,
               (byte)0xCA, (byte)0x5F, (byte)0xB5, (byte)0x09, (byte)0x6E, (byte)0x95, (byte)0xCF, (byte)0x78,
               (byte)0x7C, (byte)0x0D, (byte)0xB2});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p384",
                     "secp384r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (48, new byte[]
              {(byte)0x30, (byte)0x76, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2B,
               (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x22, (byte)0x03, (byte)0x62, (byte)0x00, (byte)0x04,
               (byte)0x63, (byte)0x5C, (byte)0x35, (byte)0x5C, (byte)0xC0, (byte)0xDF, (byte)0x90, (byte)0x16,
               (byte)0xA6, (byte)0x18, (byte)0xF1, (byte)0x50, (byte)0xA7, (byte)0x73, (byte)0xE7, (byte)0x05,
               (byte)0x22, (byte)0x36, (byte)0xF7, (byte)0xDC, (byte)0x9F, (byte)0xD8, (byte)0xA5, (byte)0xAC,
               (byte)0x71, (byte)0x9F, (byte)0x1C, (byte)0x9A, (byte)0x71, (byte)0x94, (byte)0x8B, (byte)0x81,
               (byte)0x15, (byte)0x32, (byte)0x24, (byte)0x92, (byte)0x11, (byte)0x11, (byte)0xDC, (byte)0x7E,
               (byte)0x9D, (byte)0x70, (byte)0x1A, (byte)0x9B, (byte)0x83, (byte)0x33, (byte)0x8B, (byte)0x59,
               (byte)0xC1, (byte)0x93, (byte)0x34, (byte)0x7F, (byte)0x58, (byte)0x0D, (byte)0x91, (byte)0xC4,
               (byte)0xD2, (byte)0x20, (byte)0x8F, (byte)0x64, (byte)0x16, (byte)0x16, (byte)0xEE, (byte)0x07,
               (byte)0x51, (byte)0xC3, (byte)0xF8, (byte)0x56, (byte)0x5B, (byte)0xCD, (byte)0x49, (byte)0xFE,
               (byte)0xE0, (byte)0xE2, (byte)0xD5, (byte)0xC5, (byte)0x79, (byte)0xD1, (byte)0xA6, (byte)0x18,
               (byte)0x82, (byte)0xBD, (byte)0x65, (byte)0x83, (byte)0xB6, (byte)0x84, (byte)0x77, (byte)0xE8,
               (byte)0x1F, (byte)0xB8, (byte)0xD7, (byte)0x3D, (byte)0x79, (byte)0x88, (byte)0x2E, (byte)0x98});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.nist.p521",
                     "secp521r1",
                      ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (66, new byte[]
              {(byte)0x30, (byte)0x81, (byte)0x9B, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A,
               (byte)0x86, (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05,
               (byte)0x2B, (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x23, (byte)0x03, (byte)0x81, (byte)0x86,
               (byte)0x00, (byte)0x04, (byte)0x01, (byte)0xFC, (byte)0xA0, (byte)0x56, (byte)0x27, (byte)0xB7,
               (byte)0x68, (byte)0x25, (byte)0xC5, (byte)0x83, (byte)0xD1, (byte)0x34, (byte)0x0A, (byte)0xAE,
               (byte)0x96, (byte)0x1D, (byte)0xDC, (byte)0xE0, (byte)0x95, (byte)0xC5, (byte)0xE0, (byte)0x25,
               (byte)0x1F, (byte)0x46, (byte)0xF6, (byte)0x36, (byte)0xD7, (byte)0x3F, (byte)0xD9, (byte)0x5A,
               (byte)0x15, (byte)0xE3, (byte)0x05, (byte)0xBA, (byte)0x14, (byte)0x06, (byte)0x1B, (byte)0xEB,
               (byte)0xD4, (byte)0x88, (byte)0xFC, (byte)0x0D, (byte)0x87, (byte)0x02, (byte)0x15, (byte)0x4E,
               (byte)0x7E, (byte)0xC0, (byte)0x9F, (byte)0xF6, (byte)0x1C, (byte)0x80, (byte)0x2C, (byte)0xE6,
               (byte)0x0D, (byte)0xF5, (byte)0x0E, (byte)0x6C, (byte)0xD9, (byte)0x55, (byte)0xFA, (byte)0xBD,
               (byte)0x6B, (byte)0x55, (byte)0xA1, (byte)0x0E, (byte)0x00, (byte)0x55, (byte)0x12, (byte)0x35,
               (byte)0x8D, (byte)0xFC, (byte)0x0A, (byte)0x42, (byte)0xE5, (byte)0x78, (byte)0x09, (byte)0xD6,
               (byte)0xF6, (byte)0x0C, (byte)0xBE, (byte)0x15, (byte)0x0A, (byte)0x7D, (byte)0xC2, (byte)0x2E,
               (byte)0x98, (byte)0xA1, (byte)0xE1, (byte)0x6A, (byte)0xF1, (byte)0x1F, (byte)0xD2, (byte)0x9F,
               (byte)0x9A, (byte)0x81, (byte)0x65, (byte)0x51, (byte)0x8F, (byte)0x6E, (byte)0xF1, (byte)0x3B,
               (byte)0x95, (byte)0x6B, (byte)0xCE, (byte)0x51, (byte)0x09, (byte)0xFF, (byte)0x23, (byte)0xDC,
               (byte)0xE8, (byte)0x71, (byte)0x1A, (byte)0x94, (byte)0xC7, (byte)0x8E, (byte)0x4A, (byte)0xA9,
               (byte)0x22, (byte)0xA8, (byte)0x87, (byte)0x64, (byte)0xD0, (byte)0x36, (byte)0xAF, (byte)0xD3,
               (byte)0x69, (byte)0xAC, (byte)0xCA, (byte)0xCB, (byte)0x1A, (byte)0x96});

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#ec.brainpool.p256r1",
                     "brainpoolP256r1",
                     ALG_EC_KEY | ALG_KEY_GEN).addEcCurve (32, new byte[]
              {(byte)0x30, (byte)0x5A, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
               (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x09, (byte)0x2B,
               (byte)0x24, (byte)0x03, (byte)0x03, (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x07,
               (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x26, (byte)0x3C, (byte)0x91, (byte)0x3F,
               (byte)0x6B, (byte)0x91, (byte)0x10, (byte)0x6F, (byte)0xE4, (byte)0xA2, (byte)0x2D, (byte)0xA4,
               (byte)0xBB, (byte)0xAB, (byte)0xCE, (byte)0x9E, (byte)0x41, (byte)0x01, (byte)0x0B, (byte)0xB0,
               (byte)0xC3, (byte)0x84, (byte)0xEF, (byte)0x35, (byte)0x0D, (byte)0x66, (byte)0xEE, (byte)0x0C,
               (byte)0xEC, (byte)0x60, (byte)0xB6, (byte)0xF5, (byte)0x54, (byte)0x54, (byte)0x27, (byte)0x2A,
               (byte)0x1D, (byte)0x07, (byte)0x61, (byte)0xB0, (byte)0xC3, (byte)0x01, (byte)0xE8, (byte)0xCB,
               (byte)0x52, (byte)0xF5, (byte)0x03, (byte)0xC1, (byte)0x0C, (byte)0x3F, (byte)0xF0, (byte)0x97,
               (byte)0xCD, (byte)0xC9, (byte)0x45, (byte)0xF3, (byte)0x21, (byte)0xC5, (byte)0xCF, (byte)0x41,
               (byte)0x17, (byte)0xF3, (byte)0x3A, (byte)0xB4});

        for (short rsa_size : SecureKeyStore.SKS_DEFAULT_RSA_SUPPORT) {
            addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size,
                    null, ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            if (SKS_RSA_EXPONENT_SUPPORT) {
                addAlgorithm("http://xmlns.webpki.org/sks/algorithm#rsa" + rsa_size + ".exp",
                        null, ALG_KEY_PARM | ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            }
        }

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm(SecureKeyStore.ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm(SecureKeyStore.ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm("http://xmlns.webpki.org/sks/algorithm#none", null, ALG_NONE);

    }

    static final byte[] RSA_ENCRYPTION_OID = {0x06, 0x09, 0x2A, (byte) 0x86, 0x48, (byte) 0x86, (byte) 0xF7, 0x0D, 0x01, 0x01, 0x01};


    /////////////////////////////////////////////////////////////////////////////////////////////
    // The embedded SE "Master Key" that is the origin for the seal and integrity functions 
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] SE_MASTER_SECRET = 
           {(byte) 0x80, (byte) 0xD4, (byte) 0xCA, (byte) 0xBB, (byte) 0x8A, (byte) 0x22, (byte) 0xA3, (byte) 0xD0,
            (byte) 0x18, (byte) 0x07, (byte) 0x1A, (byte) 0xD5, (byte) 0x97, (byte) 0x8D, (byte) 0x7D, (byte) 0x22,
            (byte) 0x65, (byte) 0x40, (byte) 0x36, (byte) 0xDD, (byte) 0x28, (byte) 0xDC, (byte) 0x63, (byte) 0x73,
            (byte) 0xC5, (byte) 0xF8, (byte) 0x61, (byte) 0x1C, (byte) 0xB6, (byte) 0xB6, (byte) 0x27, (byte) 0xF8};

    /////////////////////////////////////////////////////////////////////////////////////////////
    // The SE "Master Key" is always derived 
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] SESSION_KEY_ENCRYPTION = {'S', 'e', 's', 's', 'i', 'o', 'n', 'K', 'e', 'y'};

    static final byte[] USER_KEY_ENCRYPTION = {'U', 's', 'e', 'r', 'K', 'e', 'y'};

    static final byte[] USER_KEY_INTEGRITY = {'I', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y'};

    static byte[] userKey_wrapper_secret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(USER_KEY_ENCRYPTION);
            userKey_wrapper_secret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] sessionKey_wrapper_secret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(SESSION_KEY_ENCRYPTION);
            sessionKey_wrapper_secret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] userKeyMac_secret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(USER_KEY_INTEGRITY);
            userKeyMac_secret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static final char[] ATTESTATION_KEY_PASSWORD = {'t', 'e', 's', 't', 'i', 'n', 'g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";

    static class ByteReader extends DataInputStream {
        ByteReader(byte[] input) {
            super(new ByteArrayInputStream(input));
        }

        byte[] readArray(int expectedLength) throws IOException {
            int length = readUnsignedShort();
            if (expectedLength > 0 && expectedLength != length) {
                throw new IOException("Array length error");
            }
            byte[] data = new byte[length];
            readFully(data);
            return data;
        }

        byte[] getArray() throws IOException {
            return readArray(0);
        }

        void checkEOF() throws IOException {
            if (read() != -1) {
                throw new IOException("Length error reading sealed data");
            }
        }
    }

    static class ByteWriter {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream das = new DataOutputStream(baos);

        void writeBoolean(boolean value) throws IOException {
            das.writeBoolean(value);
        }

        void writeArray(byte[] value) throws IOException {
            das.writeShort(value.length);
            das.write(value);
        }

        public byte[] getData() throws IOException {
            das.flush();
            return baos.toByteArray();
        }

        void writeShort(int value) throws IOException {
            das.writeShort(value);
        }
    }

    static class UnwrappedKey {
        byte[] wrappedKey;

        boolean isSymmetric;

        boolean isExportable;

        byte[] sha256OfPublicKeyOrCertificate;

        PrivateKey privateKey;

        byte[] symmetricKey;

        boolean isRSA() {
            return privateKey instanceof RSAKey;
        }

        private byte[] createMAC(byte[] osInstanceKey) throws GeneralSecurityException {
            MacBuilder macBuilder = new MacBuilder(deriveKey(osInstanceKey, userKeyMac_secret));
            macBuilder.addBool(isExportable);
            macBuilder.addBool(isSymmetric);
            macBuilder.addArray(wrappedKey);
            return macBuilder.getResult();
        }

        byte[] writeKey(byte[] osInstanceKey) throws GeneralSecurityException {
            try {
                ByteWriter byte_writer = new ByteWriter();
                byte_writer.writeArray(wrappedKey);
                byte_writer.writeBoolean(isSymmetric);
                byte_writer.writeBoolean(isExportable);
                byte_writer.writeArray(sha256OfPublicKeyOrCertificate);
                byte_writer.writeArray(createMAC(osInstanceKey));
                return byte_writer.getData();
            } catch (IOException e) {
                throw new GeneralSecurityException(e);
            }
        }

        void readKey(byte[] osInstanceKey, byte[] sealedKey) throws GeneralSecurityException {
            try {
                ByteReader byte_reader = new ByteReader(sealedKey);
                wrappedKey = byte_reader.getArray();
                isSymmetric = byte_reader.readBoolean();
                isExportable = byte_reader.readBoolean();
                sha256OfPublicKeyOrCertificate = byte_reader.readArray(32);
                byte[] oldMac = byte_reader.readArray(32);
                byte_reader.checkEOF();
                if (!Arrays.equals(oldMac, createMAC(osInstanceKey))) {
                    throw new GeneralSecurityException("Sealed key MAC error");
                }
            } catch (IOException e) {
                throw new GeneralSecurityException(e);
            }
        }
    }

    static class UnwrappedSessionKey {
        byte[] sessionKey;

        byte[] wrappedSessionKey;

        short macSequenceCounter;

        short sessionKeyLimit;

        public void readKey(byte[] provisioningState) throws GeneralSecurityException {
            try {
                ByteReader byte_reader = new ByteReader(provisioningState);
                wrappedSessionKey = byte_reader.readArray(SecureKeyStore.AES_CBC_PKCS5_PADDING + 32);
                macSequenceCounter = byte_reader.readShort();
                sessionKeyLimit = byte_reader.readShort();
                byte_reader.checkEOF();
            } catch (IOException e) {
                throw new GeneralSecurityException(e);
            }
        }

        byte[] writeKey() throws SKSException {
            try {
                ByteWriter byte_writer = new ByteWriter();
                byte_writer.writeArray(wrappedSessionKey);
                byte_writer.writeShort(macSequenceCounter);
                byte_writer.writeShort(sessionKeyLimit);
                return byte_writer.getData();
            } catch (IOException e) {
                throw new SKSException(e);
            }
        }
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // Utility Functions
    /////////////////////////////////////////////////////////////////////////////////////////////

    static byte[] deriveKey(byte[] osInstanceKey, byte[] originalKey) throws GeneralSecurityException {
        if (osInstanceKey.length != 32) {
            throw new GeneralSecurityException("\"osInstanceKey\" length error: " + osInstanceKey.length);
        }
        byte[] result = new byte[32];
        for (int i = 0; i < 32; i++) {
            result[i] = (byte) (osInstanceKey[i] ^ originalKey[i]);
        }
        return result;
    }

    static UnwrappedKey getUnwrappedKey(byte[] osInstanceKey, byte[] sealedKey) throws SKSException {
        UnwrappedKey unwrappedKey = new UnwrappedKey();
        try {
            unwrappedKey.readKey(osInstanceKey, sealedKey);
            byte[] data = unwrappedKey.wrappedKey;
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(osInstanceKey, userKey_wrapper_secret), "AES"), new IvParameterSpec(data, 0, 16));
            byte[] rawKey = crypt.doFinal(data, 16, data.length - 16);
            if (unwrappedKey.isSymmetric) {
                unwrappedKey.isSymmetric = true;
                unwrappedKey.symmetricKey = rawKey;
            } else {
                unwrappedKey.privateKey = raw2PrivateKey(rawKey);
            }
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        return unwrappedKey;
    }

    static byte[] wrapKey(byte[] osInstanceKey, UnwrappedKey unwrappedKey, byte[] rawKey) throws GeneralSecurityException {
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveKey(osInstanceKey, userKey_wrapper_secret), "AES"), new IvParameterSpec(iv));
        unwrappedKey.wrappedKey = addArrays(iv, crypt.doFinal(rawKey));
        return unwrappedKey.writeKey(osInstanceKey);
    }

    static UnwrappedSessionKey getUnwrappedSessionKey(byte[] osInstanceKey, byte[] provisioningState) throws SKSException {
        UnwrappedSessionKey unwrappedSessionKey = new UnwrappedSessionKey();
        try {
            unwrappedSessionKey.readKey(provisioningState);
            byte[] data = unwrappedSessionKey.wrappedSessionKey;
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(deriveKey(osInstanceKey, sessionKey_wrapper_secret), "AES"), new IvParameterSpec(data, 0, 16));
            unwrappedSessionKey.sessionKey = crypt.doFinal(data, 16, data.length - 16);
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        return unwrappedSessionKey;
    }

    static byte[] wrapSessionKey(byte[] osInstanceKey, UnwrappedSessionKey unwrappedSessionKey, byte[] rawKey, short sessionKeyLimit) throws GeneralSecurityException, SKSException {
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(deriveKey(osInstanceKey, sessionKey_wrapper_secret), "AES"), new IvParameterSpec(iv));
        unwrappedSessionKey.wrappedSessionKey = addArrays(iv, crypt.doFinal(rawKey));
        unwrappedSessionKey.sessionKeyLimit = sessionKeyLimit;
        return unwrappedSessionKey.writeKey();
    }

    static KeyStore getAttestationKeyStore() throws GeneralSecurityException {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(SEReferenceImplementation.class.getResourceAsStream("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
            return ks;
        } catch (IOException e) {
            throw new GeneralSecurityException(e);
        }
    }

    static X509Certificate[] getDeviceCertificatePath() throws GeneralSecurityException {
        return new X509Certificate[]{(X509Certificate) getAttestationKeyStore().getCertificate(ATTESTATION_KEY_ALIAS)};
    }

    static byte[] getDeviceID(boolean privacyEnabled) throws GeneralSecurityException {
        return privacyEnabled ? SecureKeyStore.KDF_ANONYMOUS : getDeviceCertificatePath()[0].getEncoded();
    }

    static PrivateKey getAttestationKey() throws GeneralSecurityException {
        return (PrivateKey) getAttestationKeyStore().getKey(ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);
    }

    static int getShort(byte[] buffer, int index) {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
    }

    static void abort(String message) throws SKSException {
        throw new SKSException(message);
    }

    static void abort(String message, int option) throws SKSException {
        throw new SKSException(message, option);
    }

    static void abort(Exception e) throws SKSException {
        throw new SKSException(e, SKSException.ERROR_CRYPTO);
    }

    static void checkIDSyntax(String identifier, String symbolic_name) throws SKSException {
        boolean flag = false;
        if (identifier.length() == 0 || identifier.length() > SecureKeyStore.MAX_LENGTH_ID_TYPE) {
            flag = true;
        } else for (char c : identifier.toCharArray()) {
            /////////////////////////////////////////////////
            // The restricted ID
            /////////////////////////////////////////////////
            if (c < '!' || c > '~') {
                flag = true;
                break;
            }
        }
        if (flag) {
            abort("Malformed \"" + symbolic_name + "\" : " + identifier);
        }
    }

    static Algorithm getEcType(ECKey ecKey) {
        for (String uri : supportedAlgorithms.keySet()) {
            ECParameterSpec ecParameterSpec = supportedAlgorithms.get(uri).ecParameterSpec;
            if (ecParameterSpec != null &&
                    ecKey.getParams().getCurve().equals(ecParameterSpec.getCurve()) &&
                    ecKey.getParams().getGenerator().equals(ecParameterSpec.getGenerator())) {
                return supportedAlgorithms.get(uri);
            }
        }
        return null;
    }

    static int getEcPointLength(ECKey ecKey) throws GeneralSecurityException {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.ecPointLength;
        }
        throw new GeneralSecurityException("Unsupported EC curve");
    }

    static String checkECKeyCompatibility(ECKey ecKey, String keyId) throws SKSException {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.jceName;
        }
        abort("Unsupported EC key algorithm for: " + keyId);
        return null;
    }

    static void checkRSAKeyCompatibility(int rsaKey_size, BigInteger exponent, String keyId) throws SKSException {
        if (!SKS_RSA_EXPONENT_SUPPORT && !exponent.equals(RSAKeyGenParameterSpec.F4)) {
            abort("Unsupported RSA exponent value for: " + keyId);
        }
        boolean found = false;
        for (short key_size : SecureKeyStore.SKS_DEFAULT_RSA_SUPPORT) {
            if (key_size == rsaKey_size) {
                found = true;
                break;
            }
        }
        if (!found) {
            abort("Unsupported RSA key size " + rsaKey_size + " for: " + keyId);
        }
    }

    static int getRSAKeySize(RSAKey rsaKey) {
        byte[] modblob = rsaKey.getModulus().toByteArray();
        return (modblob[0] == 0 ? modblob.length - 1 : modblob.length) * 8;
    }

    static byte[] addArrays(byte[] a, byte[] b) {
        byte[] r = new byte[a.length + b.length];
        System.arraycopy(a, 0, r, 0, a.length);
        System.arraycopy(b, 0, r, a.length, b.length);
        return r;
    }

    static class MacBuilder implements Serializable {
        private static final long serialVersionUID = 1L;

        Mac mac;

        MacBuilder(byte[] key) throws GeneralSecurityException {
            mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "RAW"));
        }

        MacBuilder addVerbatim(byte[] data) {
            mac.update(data);
            return this;
        }

        void addArray(byte[] data) {
            addShort(data.length);
            mac.update(data);
        }

        void addBlob(byte[] data) {
            addInt(data.length);
            mac.update(data);
        }

        void addString(String string) throws SKSException {
            try {
                addArray(string.getBytes("UTF-8"));
            } catch (IOException e) {
                abort("Internal UTF-8");
            }
        }

        void addInt(int i) {
            mac.update((byte) (i >>> 24));
            mac.update((byte) (i >>> 16));
            mac.update((byte) (i >>> 8));
            mac.update((byte) i);
        }

        void addShort(int s) {
            mac.update((byte) (s >>> 8));
            mac.update((byte) s);
        }

        void addByte(byte b) {
            mac.update(b);
        }

        void addBool(boolean flag) {
            mac.update(flag ? (byte) 0x01 : (byte) 0x00);
        }

        byte[] getResult() {
            return mac.doFinal();
        }

        void verify(byte[] claimedMac) throws SKSException {
            if (!Arrays.equals(getResult(), claimedMac)) {
                abort("MAC error", SKSException.ERROR_MAC);
            }
        }
    }

    static class AttestationSignatureGenerator {
        SignatureWrapper signer;

        AttestationSignatureGenerator() throws GeneralSecurityException {
            PrivateKey attester = getAttestationKey();
            signer = new SignatureWrapper(attester instanceof RSAPrivateKey ? "SHA256withRSA" : "SHA256withECDSA",
                    attester);
        }

        private byte[] short2bytes(int s) {
            return new byte[]{(byte) (s >>> 8), (byte) s};
        }

        private byte[] int2bytes(int i) {
            return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
        }

        void addBlob(byte[] data) throws GeneralSecurityException {
            signer.update(int2bytes(data.length));
            signer.update(data);
        }

        void addArray(byte[] data) throws GeneralSecurityException {
            signer.update(short2bytes(data.length));
            signer.update(data);
        }

        void addString(String string) throws IOException, GeneralSecurityException {
            addArray(string.getBytes("UTF-8"));
        }

        void addInt(int i) throws GeneralSecurityException {
            signer.update(int2bytes(i));
        }

        void addShort(int s) throws GeneralSecurityException {
            signer.update(short2bytes(s));
        }

        void addByte(byte b) throws GeneralSecurityException {
            signer.update(b);
        }

        void addBool(boolean flag) throws GeneralSecurityException {
            signer.update(flag ? (byte) 0x01 : (byte) 0x00);
        }

        byte[] getResult() throws GeneralSecurityException {
            return signer.sign();
        }
    }

    static MacBuilder getMacBuilder(UnwrappedSessionKey unwrappedSessionKey, byte[] keyModifier) throws SKSException {
        if (unwrappedSessionKey.sessionKeyLimit-- <= 0) {
            abort("\"SessionKeyLimit\" exceeded");
        }
        try {
            return new MacBuilder(addArrays(unwrappedSessionKey.sessionKey, keyModifier));
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
    }

    static MacBuilder getMacBuilderForMethodCall(UnwrappedSessionKey unwrappedSessionKey, byte[] method) throws SKSException {
        short q = unwrappedSessionKey.macSequenceCounter++;
        return getMacBuilder(unwrappedSessionKey, addArrays(method, new byte[]{(byte) (q >>> 8), (byte) q}));
    }

    static MacBuilder getEECertMacBuilder(UnwrappedSessionKey unwrappedSessionKey,
                                          UnwrappedKey unwrappedKey,
                                          X509Certificate eeCertificate,
                                          byte[] method) throws SKSException, GeneralSecurityException {
        byte[] binEe = eeCertificate.getEncoded();
        if (!Arrays.equals(unwrappedKey.sha256OfPublicKeyOrCertificate, getSHA256(binEe))) {
            throw new GeneralSecurityException("\"EECertificate\" Inconsistency test failed");
        }
        MacBuilder macBuilder = getMacBuilderForMethodCall(unwrappedSessionKey, method);
        macBuilder.addArray(binEe);
        return macBuilder;
    }

    static byte[] decrypt(UnwrappedSessionKey unwrappedSessionKey, byte[] data) throws SKSException {
        byte[] key = getMacBuilder(unwrappedSessionKey,
                SecureKeyStore.ZERO_LENGTH_ARRAY).addVerbatim(SecureKeyStore.KDF_ENCRYPTION_KEY).getResult();
        try {
            Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
            crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(data, 0, 16));
            return crypt.doFinal(data, 16, data.length - 16);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e);
        }
    }

    static boolean verifyKeyManagementKeyAuthorization(PublicKey keyManagementKey,
                                                       byte[] kmkKdf,
                                                       byte[] argument,
                                                       byte[] authorization) throws GeneralSecurityException {
        return new SignatureWrapper(keyManagementKey instanceof RSAPublicKey ? "SHA256WithRSA" : "SHA256WithECDSA",
                                    keyManagementKey)
            .update(kmkKdf)
            .update(argument)
            .verify(authorization);
    }

    static void validateTargetKeyLocal(MacBuilder verifier,
                                       PublicKey keyManagementKey,
                                       X509Certificate targetKeyEeCertificate,
                                       int targetKeyHandle,
                                       byte[] authorization,
                                       boolean privacyEnabled,
                                       UnwrappedSessionKey unwrappedSessionKey,
                                       byte[] mac) throws SKSException, GeneralSecurityException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify MAC
        ///////////////////////////////////////////////////////////////////////////////////
        verifier.addArray(authorization);
        verifier.verify(mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KMK signature
        ///////////////////////////////////////////////////////////////////////////////////
        if (!verifyKeyManagementKeyAuthorization(keyManagementKey,
                                                 SecureKeyStore.KMK_TARGET_KEY_REFERENCE,
                                                 getMacBuilder(unwrappedSessionKey,
                                                 getDeviceID(privacyEnabled))
                                                     .addVerbatim(targetKeyEeCertificate.getEncoded()).getResult(),
                                                 authorization)) {
            abort("\"" + SecureKeyStore.VAR_AUTHORIZATION + "\" signature did not verify for key #" + targetKeyHandle);
        }
    }

    static Algorithm getAlgorithm(String algorithm_uri) throws SKSException {
        Algorithm alg = supportedAlgorithms.get(algorithm_uri);
        if (alg == null) {
            abort("Unsupported algorithm: " + algorithm_uri, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    static void testSymmetricKey(String algorithm,
                                 byte[] symmetricKey,
                                 String keyId) throws SKSException {
        Algorithm alg = getAlgorithm(algorithm);
        if ((alg.mask & ALG_SYM_ENC) != 0) {
            int l = symmetricKey.length;
            if (l == 16) l = ALG_SYML_128;
            else if (l == 24) l = ALG_SYML_192;
            else if (l == 32) l = ALG_SYML_256;
            else
                l = 0;
            if ((l & alg.mask) == 0) {
                abort("Key " + keyId + " has wrong size (" + symmetricKey.length + ") for algorithm: " + algorithm);
            }
        }
    }

    static Algorithm checkKeyAndAlgorithm(UnwrappedKey unwrappedKey, int keyHandle, String algorithm, int expectedType) throws SKSException {
        Algorithm alg = getAlgorithm(algorithm);
        if ((alg.mask & expectedType) == 0) {
            abort("Algorithm does not match operation: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ unwrappedKey.isSymmetric) {
            abort((unwrappedKey.isSymmetric ? "S" : "As") + "ymmetric key #" + keyHandle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        if (unwrappedKey.isSymmetric) {
            testSymmetricKey(algorithm, unwrappedKey.symmetricKey, "#" + keyHandle);
        } else if (unwrappedKey.isRSA() ^ (alg.mask & ALG_RSA_KEY) != 0) {
            abort((unwrappedKey.isRSA() ? "RSA" : "EC") + " key #" + keyHandle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    public static void testKeyAndAlgorithmCompliance(byte[] osInstanceKey,
                                                     byte[] sealedKey,
                                                     String algorithm,
                                                     String id) throws SKSException {
        Algorithm alg = getAlgorithm(algorithm);
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
        if ((alg.mask & ALG_NONE) == 0) {
            ///////////////////////////////////////////////////////////////////////////////////
            // A non-null endorsed algorithm found.  Symmetric or asymmetric key?
            ///////////////////////////////////////////////////////////////////////////////////
            if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) == 0) ^ unwrappedKey.isSymmetric) {
                if (unwrappedKey.isSymmetric) {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Symmetric. AES algorithms only operates on 128, 192, and 256 bit keys
                    ///////////////////////////////////////////////////////////////////////////////////
                    testSymmetricKey(algorithm, unwrappedKey.symmetricKey, id);
                    return;
                } else {
                    ///////////////////////////////////////////////////////////////////////////////////
                    // Asymmetric.  Check that algorithms match RSA or EC
                    ///////////////////////////////////////////////////////////////////////////////////
                    if (((alg.mask & ALG_RSA_KEY) == 0) ^ unwrappedKey.isRSA()) {
                        return;
                    }
                }
            }
            abort((unwrappedKey.isSymmetric ? "Symmetric" : unwrappedKey.isRSA() ? "RSA" : "EC") +
                    " key " + id + " does not match algorithm: " + algorithm);
        }
    }

    static byte[] getSHA256(byte[] encoded) throws GeneralSecurityException {
        return MessageDigest.getInstance("SHA-256").digest(encoded);
    }

    static PrivateKey raw2PrivateKey(byte[] pkcs8PrivateKey) throws GeneralSecurityException {
        PKCS8EncodedKeySpec key_spec = new PKCS8EncodedKeySpec(pkcs8PrivateKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Bare-bones ASN.1 decoding to find out if it is RSA or EC 
        ///////////////////////////////////////////////////////////////////////////////////
        boolean rsaFlag = false;
        for (int j = 8; j < 11; j++) {
            rsaFlag = true;
            for (int i = 0; i < RSA_ENCRYPTION_OID.length; i++) {
                if (pkcs8PrivateKey[j + i] != RSA_ENCRYPTION_OID[i]) {
                    rsaFlag = false;
                }
            }
            if (rsaFlag) break;
        }
        return KeyFactory.getInstance(rsaFlag ? "RSA" : "EC").generatePrivate(key_spec);
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // PKCS #1 Signature Support Data
    /////////////////////////////////////////////////////////////////////////////////////////////
    static final byte[] DIGEST_INFO_SHA1 = 
           {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02,
            0x1a, 0x05, 0x00, 0x04, 0x14};

    static final byte[] DIGEST_INFO_SHA256 =
           {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, (byte) 0x86, 0x48,
            0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20};


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEDeviceInfo getDeviceInfo() throws SKSException {
        try {
            return new SEDeviceInfo(SecureKeyStore.SKS_API_LEVEL,
                                    (byte) (DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE),
                                    SKS_UPDATE_URL,
                                    SKS_VENDOR_NAME,
                                    SKS_VENDOR_DESCRIPTION,
                                    getDeviceCertificatePath(),
                                    supportedAlgorithms.keySet().toArray(new String[0]),
                                    MAX_LENGTH_CRYPTO_DATA,
                                    MAX_LENGTH_EXTENSION_DATA);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              checkKeyPair                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static void checkKeyPair(byte[] osInstanceKey,
                                    byte[] sealedKey,
                                    PublicKey publicKey,
                                    String id) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Perform "sanity" checks
        ///////////////////////////////////////////////////////////////////////////////////
        if (publicKey instanceof RSAPublicKey ^ unwrappedKey.isRSA()) {
            abort("RSA/EC mixup between public and private keys for: " + id);
        }
        if (unwrappedKey.isRSA()) {
            if (!((RSAPublicKey) publicKey).getPublicExponent().equals(((RSAPrivateCrtKey) unwrappedKey.privateKey).getPublicExponent()) ||
                    !((RSAPublicKey) publicKey).getModulus().equals(((RSAPrivateKey) unwrappedKey.privateKey).getModulus())) {
                abort("RSA mismatch between public and private keys for: " + id);
            }
        } else {
            try {
                Signature ec_signer = Signature.getInstance("SHA256withECDSA");
                ec_signer.initSign(unwrappedKey.privateKey);
                ec_signer.update(RSA_ENCRYPTION_OID);  // Any data could be used...
                byte[] ec_signData = ec_signer.sign();
                Signature ec_verifier = Signature.getInstance("SHA256withECDSA");
                ec_verifier.initVerify(publicKey);
                ec_verifier.update(RSA_ENCRYPTION_OID);
                if (!ec_verifier.verify(ec_signData)) {
                    abort("EC mismatch between public and private keys for: " + id);
                }
            } catch (GeneralSecurityException e) {
                abort(e);
            }
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           executeSessionSign                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSessionSign(byte[] osInstanceKey,
                                            byte[] provisioningState,
                                            byte[] data) throws SKSException {
        return getMacBuilder(getUnwrappedSessionKey(osInstanceKey, provisioningState),
                SecureKeyStore.KDF_EXTERNAL_SIGNATURE).addVerbatim(data).getResult();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        executeAsymmetricDecrypt                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeAsymmetricDecrypt(byte[] osInstanceKey,
                                                  byte[] sealedKey,
                                                  int keyHandle,
                                                  String algorithm,
                                                  byte[] parameters,
                                                  byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(unwrappedKey, keyHandle, algorithm, ALG_ASYM_ENC);
        if (parameters != null)  // Only support basic RSA yet...
        {
            abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Cipher cipher = Cipher.getInstance(alg.jceName);
            cipher.init(Cipher.DECRYPT_MODE, unwrappedKey.privateKey);
            return cipher.doFinal(data);
        } catch (Exception e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            executeSignHash                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSignHash(byte[] osInstanceKey,
                                         byte[] sealedKey,
                                         int keyHandle,
                                         String algorithm,
                                         byte[] parameters,
                                         byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(unwrappedKey, keyHandle, algorithm, ALG_ASYM_SGN);
        int hashLen = (alg.mask / ALG_HASH_DIV) & ALG_HASH_MSK;
        if (hashLen > 0 && hashLen != data.length) {
            abort("Incorrect length of \"" + SecureKeyStore.VAR_DATA + "\": " + data.length);
        }
        if (parameters != null)  // Only supports non-parameterized operations yet...
        {
            abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            if (unwrappedKey.isRSA() && hashLen > 0) {
                data = addArrays(alg.pkcs1DigestInfo, data);
            }
            return new SignatureWrapper(alg.jceName, unwrappedKey.privateKey)
                    .update(data)
                    .sign();
        } catch (Exception e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               executeHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeHMAC(byte[] osInstanceKey,
                                     byte[] sealedKey,
                                     int keyHandle,
                                     String algorithm,
                                     byte[] parameters,
                                     byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(unwrappedKey, keyHandle, algorithm, ALG_HMAC);
        if (parameters != null) {
            abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" does not apply to: " + algorithm);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Mac mac = Mac.getInstance(alg.jceName);
            mac.init(new SecretKeySpec(unwrappedKey.symmetricKey, "RAW"));
            return mac.doFinal(data);
        } catch (GeneralSecurityException e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      executeSymmetricEncryption                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeSymmetricEncryption(byte[] osInstanceKey,
                                                    byte[] sealedKey,
                                                    int keyHandle,
                                                    String algorithm,
                                                    boolean mode,
                                                    byte[] parameters,
                                                    byte[] data) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(unwrappedKey, keyHandle, algorithm, ALG_SYM_ENC);
        if ((alg.mask & ALG_IV_REQ) == 0 || (alg.mask & ALG_IV_INT) != 0) {
            if (parameters != null) {
                abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" does not apply to: " + algorithm);
            }
        } else if (parameters == null || parameters.length != 16) {
            abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" must be 16 bytes for: " + algorithm);
        }
        if ((!mode || (alg.mask & ALG_AES_PAD) != 0) && data.length % 16 != 0) {
            abort("Data must be a multiple of 16 bytes for: " + algorithm + (mode ? " encryption" : " decryption"));
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            Cipher crypt = Cipher.getInstance(alg.jceName);
            SecretKeySpec sk = new SecretKeySpec(unwrappedKey.symmetricKey, "AES");
            int jceMode = mode ? Cipher.ENCRYPT_MODE : Cipher.DECRYPT_MODE;
            if ((alg.mask & ALG_IV_INT) != 0) {
                parameters = new byte[16];
                if (mode) {
                    new SecureRandom().nextBytes(parameters);
                } else {
                    byte[] temp = new byte[data.length - 16];
                    System.arraycopy(data, 0, parameters, 0, 16);
                    System.arraycopy(data, 16, temp, 0, temp.length);
                    data = temp;
                }
            }
            if (parameters == null) {
                crypt.init(jceMode, sk);
            } else {
                crypt.init(jceMode, sk, new IvParameterSpec(parameters));
            }
            data = crypt.doFinal(data);
            return (mode && (alg.mask & ALG_IV_INT) != 0) ? addArrays(parameters, data) : data;
        } catch (GeneralSecurityException e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         executeKeyAgreement                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] executeKeyAgreement(byte[] osInstanceKey,
                                             byte[] sealedKey,
                                             int keyHandle,
                                             String algorithm,
                                             byte[] parameters,
                                             ECPublicKey publicKey) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the key to use
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check input arguments
        ///////////////////////////////////////////////////////////////////////////////////
        Algorithm alg = checkKeyAndAlgorithm(unwrappedKey, keyHandle, algorithm, ALG_ASYM_KA);
        if (parameters != null) // Only support external KDFs yet...
        {
            abort("\"" + SecureKeyStore.VAR_PARAMETERS + "\" for key #" + keyHandle + " do not match algorithm");
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check that the key type matches the algorithm
        ///////////////////////////////////////////////////////////////////////////////////
        checkECKeyCompatibility(publicKey, "\"" + SecureKeyStore.VAR_PUBLIC_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Finally, perform operation
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            KeyAgreement keyAgreement = KeyAgreement.getInstance(alg.jceName);
            keyAgreement.init(unwrappedKey.privateKey);
            keyAgreement.doPhase(publicKey, true);
            return keyAgreement.generateSecret();
        } catch (GeneralSecurityException e) {
            throw new SKSException(e, SKSException.ERROR_CRYPTO);
        }
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              unwrapKey                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] unwrapKey(byte[] osInstanceKey, byte[] sealedKey) throws SKSException {
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
        if (unwrappedKey.isExportable) {
            return unwrappedKey.isSymmetric ? unwrappedKey.symmetricKey : unwrappedKey.privateKey.getEncoded();
        }
        throw new SKSException("TEE export violation attempt");
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey2                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] validateTargetKey2(byte[] osInstanceKey,
                                            X509Certificate targetKeyEeCertificate,
                                            int targetKeyHandle,
                                            PublicKey keyManagementKey,
                                            X509Certificate eeCertificate,
                                            byte[] sealedKey,
                                            boolean privacyEnabled,
                                            byte[] method,
                                            byte[] authorization,
                                            byte[] provisioningState,
                                            byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

        ///////////////////////////////////////////////////////////////////////////////////
        // Unwrap the new key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate
            ///////////////////////////////////////////////////////////////////////////////////
            validateTargetKeyLocal(getEECertMacBuilder(unwrappedSessionKey,
                                                       unwrappedKey,
                                                       eeCertificate,
                                                       method),
                                   keyManagementKey,
                                   targetKeyEeCertificate,
                                   targetKeyHandle,
                                   authorization,
                                   privacyEnabled,
                                   unwrappedSessionKey,
                                   mac);
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrappedSessionKey.writeKey();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] validateTargetKey(byte[] osInstanceKey,
                                           X509Certificate targetKeyEeCertificate,
                                           int targetKeyHandle,
                                           PublicKey keyManagementKey,
                                           boolean privacyEnabled,
                                           byte[] method,
                                           byte[] authorization,
                                           byte[] provisioningState,
                                           byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate
            ///////////////////////////////////////////////////////////////////////////////////
            validateTargetKeyLocal(getMacBuilderForMethodCall(unwrappedSessionKey, method),
                                   keyManagementKey,
                                   targetKeyEeCertificate,
                                   targetKeyHandle,
                                   authorization,
                                   privacyEnabled,
                                   unwrappedSessionKey,
                                   mac);
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrappedSessionKey.writeKey();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                     validateRollOverAuthorization                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static boolean validateRollOverAuthorization(PublicKey newKeyManagementKey,
                                                        PublicKey oldKeyManagementKey,
                                                        byte[] authorization) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Verify KMK signature
        ///////////////////////////////////////////////////////////////////////////////////
        try {
            return verifyKeyManagementKeyAuthorization(oldKeyManagementKey,
                                                       SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                                                       newKeyManagementKey.getEncoded(),
                                                       authorization);
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        return false;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         closeProvisioningAttest                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] closeProvisioningAttest(byte[] osInstanceKey,
                                                 byte[] provisioningState,
                                                 String serverSessionId,
                                                 String clientSessionId,
                                                 String issuerUri,
                                                 byte[] nonce,
                                                 byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax(clientSessionId, SecureKeyStore.VAR_CLIENT_SESSION_ID);
        checkIDSyntax(serverSessionId, SecureKeyStore.VAR_SERVER_SESSION_ID);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, 
                                                         SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION);
        verifier.addString(clientSessionId);
        verifier.addString(serverSessionId);
        verifier.addString(issuerUri);
        verifier.addArray(nonce);
        verifier.verify(mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Generate the attestation in advance => checking SessionKeyLimit before "commit"
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder closeAttestation = getMacBuilderForMethodCall(unwrappedSessionKey,
                                                                 SecureKeyStore.KDF_DEVICE_ATTESTATION);
        closeAttestation.addArray(nonce);
        return closeAttestation.getResult();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         createProvisioningData                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEProvisioningData createProvisioningData(byte[] osInstanceKey,
                                                            String sessionKeyAlgorithm,
                                                            boolean privacyEnabled,
                                                            String serverSessionId,
                                                            ECPublicKey serverEphemeralKey,
                                                            String issuerUri,
                                                            PublicKey keyManagementKey, // May be null
                                                            int clientTime,
                                                            int sessionLifeTime,
                                                            short sessionKeyLimit) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Check provisioning session algorithm compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (!sessionKeyAlgorithm.equals(SecureKeyStore.ALGORITHM_SESSION_ATTEST_1)) {
            abort("Unknown \"" + SecureKeyStore.VAR_SESSION_KEY_ALGORITHM + "\" : " + sessionKeyAlgorithm);
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check IssuerURI
        ///////////////////////////////////////////////////////////////////////////////////
        if (issuerUri.length() == 0 || issuerUri.length() > SecureKeyStore.MAX_LENGTH_URI) {
            abort("\"" + SecureKeyStore.VAR_ISSUER_URI + "\" length error: " + issuerUri.length());
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax(serverSessionId, SecureKeyStore.VAR_SERVER_SESSION_ID);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check server ECDH key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        String jceName = checkECKeyCompatibility(serverEphemeralKey, "\"" + SecureKeyStore.VAR_SERVER_EPHEMERAL_KEY + "\"");

        ///////////////////////////////////////////////////////////////////////////////////
        // Check optional key management key compatibility
        ///////////////////////////////////////////////////////////////////////////////////
        if (keyManagementKey != null) {
            if (keyManagementKey instanceof RSAPublicKey) {
                checkRSAKeyCompatibility(getRSAKeySize((RSAPublicKey) keyManagementKey),
                        ((RSAPublicKey) keyManagementKey).getPublicExponent(), "\"" + SecureKeyStore.VAR_KEY_MANAGEMENT_KEY + "\"");
            } else {
                checkECKeyCompatibility((ECPublicKey) keyManagementKey, "\"" + SecureKeyStore.VAR_KEY_MANAGEMENT_KEY + "\"");
            }
        }

        ///////////////////////////////////////////////////////////////////////////////////
        // Create ClientSessionID.
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] random = new byte[SecureKeyStore.MAX_LENGTH_ID_TYPE];
        new SecureRandom().nextBytes(random);
        StringBuilder buffer = new StringBuilder();
        for (byte b : random) {
            buffer.append(BASE64_URL[b & 0x3F]);
        }
        String clientSessionId = buffer.toString();

        ///////////////////////////////////////////////////////////////////////////////////
        // Prepare for the big crypto...
        ///////////////////////////////////////////////////////////////////////////////////
        SEProvisioningData seProvisioningData = new SEProvisioningData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Create client ephemeral key
            ///////////////////////////////////////////////////////////////////////////////////
            KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
            ECGenParameterSpec eccgen = new ECGenParameterSpec(jceName);
            generator.initialize(eccgen, new SecureRandom());
            KeyPair kp = generator.generateKeyPair();
            ECPublicKey clientEphemeralKey = (ECPublicKey) kp.getPublic();

            ///////////////////////////////////////////////////////////////////////////////////
            // Apply the SP800-56A ECC CDH primitive
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement keyAgreement = KeyAgreement.getInstance("ECDH");
            keyAgreement.init(kp.getPrivate());
            keyAgreement.doPhase(serverEphemeralKey, true);
            byte[] Z = keyAgreement.generateSecret();

            ///////////////////////////////////////////////////////////////////////////////////
            // Use a custom KDF
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder kdf = new MacBuilder(Z);
            kdf.addString(clientSessionId);
            kdf.addString(serverSessionId);
            kdf.addString(issuerUri);
            kdf.addArray(getDeviceID(privacyEnabled));
            byte[] sessionKey = kdf.getResult();

            if (privacyEnabled) {
                ///////////////////////////////////////////////////////////////////////////////////
                // SessionKey attest
                ///////////////////////////////////////////////////////////////////////////////////
                MacBuilder ska = new MacBuilder(sessionKey);
                ska.addString(clientSessionId);
                ska.addString(serverSessionId);
                ska.addString(issuerUri);
                ska.addArray(getDeviceID(privacyEnabled));
                ska.addString(sessionKeyAlgorithm);
                ska.addBool(privacyEnabled);
                ska.addArray(serverEphemeralKey.getEncoded());
                ska.addArray(clientEphemeralKey.getEncoded());
                ska.addArray(keyManagementKey == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                ska.addInt(clientTime);
                ska.addInt(sessionLifeTime);
                ska.addShort(sessionKeyLimit);
                seProvisioningData.attestation = ska.getResult();
            } else {
                ///////////////////////////////////////////////////////////////////////////////////
                // Device private key attest
                ///////////////////////////////////////////////////////////////////////////////////
                AttestationSignatureGenerator pka = new AttestationSignatureGenerator();
                pka.addString(clientSessionId);
                pka.addString(serverSessionId);
                pka.addString(issuerUri);
                pka.addArray(getDeviceID(privacyEnabled));
                pka.addString(sessionKeyAlgorithm);
                pka.addBool(privacyEnabled);
                pka.addArray(serverEphemeralKey.getEncoded());
                pka.addArray(clientEphemeralKey.getEncoded());
                pka.addArray(keyManagementKey == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                pka.addInt(clientTime);
                pka.addInt(sessionLifeTime);
                pka.addShort(sessionKeyLimit);
                seProvisioningData.attestation = pka.getResult();
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Create the wrapped session key and associated data
            ///////////////////////////////////////////////////////////////////////////////////
            seProvisioningData.provisioningState = wrapSessionKey(osInstanceKey, new UnwrappedSessionKey(), sessionKey, sessionKeyLimit);
            seProvisioningData.clientSessionId = clientSessionId;
            seProvisioningData.clientEphemeralKey = clientEphemeralKey;
        } catch (Exception e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return provisioning session data including sealed session object
        ///////////////////////////////////////////////////////////////////////////////////
        return seProvisioningData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        verifyAndImportPrivateKey                           //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEPrivateKeyData verifyAndImportPrivateKey(byte[] osInstanceKey,
                                                             byte[] provisioningState,
                                                             byte[] sealedKey,
                                                             String id,
                                                             X509Certificate eeCertificate,
                                                             byte[] encryptedKey,
                                                             byte[] mac) throws SKSException {
        SEPrivateKeyData sePrivateKeyData = new SEPrivateKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (encryptedKey.length > (MAX_LENGTH_CRYPTO_DATA + SecureKeyStore.AES_CBC_PKCS5_PADDING)) {
                abort("Private key: " + id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder(unwrappedSessionKey,
                                                      unwrappedKey,
                                                      eeCertificate,
                                                      SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY);
            verifier.addArray(encryptedKey);
            verifier.verify(mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store private key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] decryptedPrivateKey = decrypt(unwrappedSessionKey, encryptedKey);
            PrivateKey decodedPrivateKey = raw2PrivateKey(decryptedPrivateKey);
            sePrivateKeyData.provisioningState = unwrappedSessionKey.writeKey();
            sePrivateKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, decryptedPrivateKey);
            if (decodedPrivateKey instanceof RSAKey) {
                checkRSAKeyCompatibility(getRSAKeySize((RSAPrivateKey) decodedPrivateKey),
                                         ((RSAPrivateCrtKey) decodedPrivateKey).getPublicExponent(),
                                         id);
            } else {
                checkECKeyCompatibility((ECPrivateKey) decodedPrivateKey, id);
            }
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return sePrivateKeyData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       verifyAndImportSymmetricKey                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SESymmetricKeyData verifyAndImportSymmetricKey(byte[] osInstanceKey,
                                                                 byte[] provisioningState,
                                                                 byte[] sealedKey,
                                                                 String id,
                                                                 X509Certificate eeCertificate,
                                                                 byte[] encryptedKey,
                                                                 byte[] mac) throws SKSException {
        SESymmetricKeyData seSymmetricKeyData = new SESymmetricKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (encryptedKey.length > (SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + SecureKeyStore.AES_CBC_PKCS5_PADDING)) {
                abort("Symmetric key: " + id + " exceeds " + SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + " bytes");
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder(unwrappedSessionKey,
                                                      unwrappedKey,
                                                      eeCertificate,
                                                      SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY);
            verifier.addArray(encryptedKey);
            verifier.verify(mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Note: This test may appear redundant but the SKS specification is quite strict
            // and does not permit certificates and private key mismatch even if the private
            // key is never used which is the case when a symmetric keys is imported 
            ///////////////////////////////////////////////////////////////////////////////////
            checkKeyPair(osInstanceKey, sealedKey, eeCertificate.getPublicKey(), id);

            ///////////////////////////////////////////////////////////////////////////////////
            // Decrypt and store symmetric key
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] rawKey = decrypt(unwrappedSessionKey, encryptedKey);
            unwrappedKey.isSymmetric = true;
            seSymmetricKeyData.provisioningState = unwrappedSessionKey.writeKey();
            seSymmetricKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, rawKey);
            seSymmetricKeyData.symmetricKeyLength = (short) rawKey.length;
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return seSymmetricKeyData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                          verifyAndGetExtension                             //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEExtensionData verifyAndGetExtension(byte[] osInstanceKey,
                                                        byte[] provisioningState,
                                                        byte[] sealedKey,
                                                        String id,
                                                        X509Certificate eeCertificate,
                                                        String type,
                                                        byte subType,
                                                        byte[] binQualifier,
                                                        byte[] extensionData,
                                                        byte[] mac) throws SKSException {
        SEExtensionData seExtensionData = new SEExtensionData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check for length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (type.length() == 0 || type.length() > SecureKeyStore.MAX_LENGTH_URI) {
                abort("URI length error: " + type.length());
            }
            if (extensionData.length > (subType == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION ?
                    MAX_LENGTH_EXTENSION_DATA + SecureKeyStore.AES_CBC_PKCS5_PADDING
                    :
                    MAX_LENGTH_EXTENSION_DATA)) {
                abort("Extension data exceeds " + MAX_LENGTH_EXTENSION_DATA + " bytes");
            }
            if (((subType == SecureKeyStore.SUB_TYPE_LOGOTYPE) ^ (binQualifier.length != 0)) ||
                    binQualifier.length > SecureKeyStore.MAX_LENGTH_QUALIFIER) {
                abort("\"Qualifier\" length error");
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getEECertMacBuilder(unwrappedSessionKey,
                                                      unwrappedKey,
                                                      eeCertificate,
                                                      SecureKeyStore.METHOD_ADD_EXTENSION);
            verifier.addString(type);
            verifier.addByte(subType);
            verifier.addArray(binQualifier);
            verifier.addBlob(extensionData);
            verifier.verify(mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Return extension data
            ///////////////////////////////////////////////////////////////////////////////////
            seExtensionData.provisioningState = unwrappedSessionKey.writeKey();
            seExtensionData.extensionData = subType == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION ?
                    decrypt(unwrappedSessionKey, extensionData) : extensionData.clone();
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return extension data and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return seExtensionData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                       setAndVerifyCertificatePath                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SECertificateData setAndVerifyCertificatePath(byte[] osInstanceKey,
                                                                byte[] provisioningState,
                                                                byte[] sealedKey,
                                                                String id,
                                                                PublicKey publicKey,
                                                                X509Certificate[] certificatePath,
                                                                byte[] mac) throws SKSException {
        SECertificateData seCertificateData = new SECertificateData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify key consistency 
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] binPublicKey = publicKey.getEncoded();
            if (!Arrays.equals(unwrappedKey.sha256OfPublicKeyOrCertificate, getSHA256(binPublicKey))) {
                throw new GeneralSecurityException("\"" + SecureKeyStore.VAR_PUBLIC_KEY + "\" inconsistency test failed");
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
            verifier.addArray(binPublicKey);
            verifier.addString(id);
            for (X509Certificate certificate : certificatePath) {
                byte[] der = certificate.getEncoded();
                if (der.length > MAX_LENGTH_CRYPTO_DATA) {
                    abort("Certificate for: " + id + " exceeds " + MAX_LENGTH_CRYPTO_DATA + " bytes");
                }
                verifier.addArray(der);
            }
            verifier.verify(mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Update the sealed key with the certificate link
            ///////////////////////////////////////////////////////////////////////////////////
            unwrappedKey.sha256OfPublicKeyOrCertificate = getSHA256(certificatePath[0].getEncoded());
            seCertificateData.provisioningState = unwrappedSessionKey.writeKey();
            seCertificateData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, unwrappedKey.privateKey.getEncoded());
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated key and session data
        ///////////////////////////////////////////////////////////////////////////////////
        return seCertificateData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              createKeyPair                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEKeyData createKeyPair(byte[] osInstanceKey,
                                          byte[] provisioningState,
                                          String id,
                                          String keyEntryAlgorithm,
                                          byte[] serverSeed,
                                          boolean devicePinProtection,
                                          String pinPolicyId,
                                          byte[] encryptedPinValue,
                                          boolean enablePin_caching,
                                          byte biometricProtection,
                                          byte exportProtection,
                                          byte deleteProtection,
                                          byte appUsage,
                                          String friendlyName,
                                          String keyAlgorithm,
                                          byte[] keyParameters,
                                          String[] endorsedAlgorithms,
                                          byte[] mac) throws SKSException {
        SEKeyData seKeyData = new SEKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate input as much as possible
            ///////////////////////////////////////////////////////////////////////////////////
            if (!keyEntryAlgorithm.equals(SecureKeyStore.ALGORITHM_KEY_ATTEST_1)) {
                abort("Unknown \"" + SecureKeyStore.VAR_KEY_ENTRY_ALGORITHM + "\" : " + keyEntryAlgorithm, SKSException.ERROR_ALGORITHM);
            }
            if (serverSeed == null) {
                serverSeed = SecureKeyStore.ZERO_LENGTH_ARRAY;
            } else if (serverSeed.length > SecureKeyStore.MAX_LENGTH_SERVER_SEED) {
                abort("\"" + SecureKeyStore.VAR_SERVER_SEED + "\" length error: " + serverSeed.length);
            }
            Algorithm kalg = supportedAlgorithms.get(keyAlgorithm);
            if (kalg == null || (kalg.mask & ALG_KEY_GEN) == 0) {
                abort("Unsupported \"" + SecureKeyStore.VAR_KEY_ALGORITHM + "\": " + keyAlgorithm);
            }
            if ((kalg.mask & ALG_KEY_PARM) == 0 ^ keyParameters == null) {
                abort((keyParameters == null ? "Missing" : "Unexpected") + " \"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\"");
            }

            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);

            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, SecureKeyStore.METHOD_CREATE_KEY_ENTRY);
            verifier.addString(id);
            verifier.addString(keyEntryAlgorithm);
            verifier.addArray(serverSeed);
            verifier.addString(pinPolicyId);
            byte[] decryptedPinValue = null;
            if (encryptedPinValue == null) {
                verifier.addString(SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
            } else {
                verifier.addArray(encryptedPinValue);
                decryptedPinValue = decrypt(unwrappedSessionKey, encryptedPinValue);
            }
            verifier.addBool(devicePinProtection);
            verifier.addBool(enablePin_caching);
            verifier.addByte(biometricProtection);
            verifier.addByte(exportProtection);
            verifier.addByte(deleteProtection);
            verifier.addByte(appUsage);
            verifier.addString(friendlyName == null ? "" : friendlyName);
            verifier.addString(keyAlgorithm);
            verifier.addArray(keyParameters == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keyParameters);
            String prevAlg = "\0";
            for (String endorsedAlgorithm : endorsedAlgorithms) {
                ///////////////////////////////////////////////////////////////////////////////////
                // Check that the algorithms are sorted and known
                ///////////////////////////////////////////////////////////////////////////////////
                if (prevAlg.compareTo(endorsedAlgorithm) >= 0) {
                    abort("Duplicate or incorrectly sorted algorithm: " + endorsedAlgorithm);
                }
                Algorithm alg = supportedAlgorithms.get(endorsedAlgorithm);
                if (alg == null || alg.mask == 0) {
                    abort("Unsupported algorithm: " + endorsedAlgorithm);
                }
                if ((alg.mask & ALG_NONE) != 0 && endorsedAlgorithms.length > 1) {
                    abort("Algorithm must be alone: " + endorsedAlgorithm);
                }
                verifier.addString(prevAlg = endorsedAlgorithm);
            }
            verifier.verify(mac);

            ///////////////////////////////////////////////////////////////////////////////////
            // Decode key algorithm specifier
            ///////////////////////////////////////////////////////////////////////////////////
            AlgorithmParameterSpec algPar_spec = null;
            if ((kalg.mask & ALG_RSA_KEY) == ALG_RSA_KEY) {
                int rsaKey_size = kalg.mask & ALG_RSA_GMSK;
                BigInteger exponent = RSAKeyGenParameterSpec.F4;
                if (keyParameters != null) {
                    if (keyParameters.length == 0 || keyParameters.length > 8) {
                        abort("\"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\" length error: " + keyParameters.length);
                    }
                    exponent = new BigInteger(keyParameters);
                }
                algPar_spec = new RSAKeyGenParameterSpec(rsaKey_size, exponent);
            } else {
                algPar_spec = new ECGenParameterSpec(kalg.jceName);
            }
            ///////////////////////////////////////////////////////////////////////////////////
            // At last, generate the desired key-pair
            ///////////////////////////////////////////////////////////////////////////////////
            SecureRandom secure_random = serverSeed.length == 0 ? new SecureRandom() : new SecureRandom(serverSeed);
            KeyPairGenerator kpg = KeyPairGenerator.getInstance(algPar_spec instanceof RSAKeyGenParameterSpec ? "RSA" : "EC");
            kpg.initialize(algPar_spec, secure_random);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = getMacBuilderForMethodCall(unwrappedSessionKey, SecureKeyStore.KDF_DEVICE_ATTESTATION);
            cka.addString(id);
            cka.addArray(publicKey.getEncoded());
            byte[] attestation = cka.getResult();

            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the key return data
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = new UnwrappedKey();
            unwrappedKey.isExportable = exportProtection != SecureKeyStore.EXPORT_DELETE_PROTECTION_NOT_ALLOWED;
            unwrappedKey.sha256OfPublicKeyOrCertificate = getSHA256(publicKey.getEncoded());
            seKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, privateKey.getEncoded());
            seKeyData.provisioningState = unwrappedSessionKey.writeKey();
            seKeyData.attestation = attestation;
            seKeyData.publicKey = publicKey;
            seKeyData.decryptedPinValue = decryptedPinValue;
        } catch (GeneralSecurityException e) {
            abort(e);
        }
        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return key data and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return seKeyData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            verifyPINPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static byte[] verifyPINPolicy(byte[] osInstanceKey,
                                         byte[] provisioningState,
                                         String id,
                                         String pukPolicyId,
                                         boolean userDefined,
                                         boolean userModifiable,
                                         byte format,
                                         short retryLimit,
                                         byte grouping,
                                         byte patternRestrictions,
                                         short minLength,
                                         short maxLength,
                                         byte inputMethod,
                                         byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax(id, SecureKeyStore.VAR_ID);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, SecureKeyStore.METHOD_CREATE_PIN_POLICY);
        verifier.addString(id);
        verifier.addString(pukPolicyId);
        verifier.addBool(userDefined);
        verifier.addBool(userModifiable);
        verifier.addByte(format);
        verifier.addShort(retryLimit);
        verifier.addByte(grouping);
        verifier.addByte(patternRestrictions);
        verifier.addShort(minLength);
        verifier.addShort(maxLength);
        verifier.addByte(inputMethod);
        verifier.verify(mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        return unwrappedSessionKey.writeKey();
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getPUKValue                                   //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEPUKData getPUKValue(byte[] osInstanceKey,
                                        byte[] provisioningState,
                                        String id,
                                        byte[] pukValue,
                                        byte format,
                                        short retryLimit,
                                        byte[] mac) throws SKSException {
        ///////////////////////////////////////////////////////////////////////////////////
        // Retrieve session key
        ///////////////////////////////////////////////////////////////////////////////////
        UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, provisioningState);

        ///////////////////////////////////////////////////////////////////////////////////
        // Get value
        ///////////////////////////////////////////////////////////////////////////////////
        byte[] decryptedPukValue = decrypt(unwrappedSessionKey, pukValue);

        ///////////////////////////////////////////////////////////////////////////////////
        // Check ID syntax
        ///////////////////////////////////////////////////////////////////////////////////
        checkIDSyntax(id, SecureKeyStore.VAR_ID);

        ///////////////////////////////////////////////////////////////////////////////////
        // Verify incoming MAC
        ///////////////////////////////////////////////////////////////////////////////////
        MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, SecureKeyStore.METHOD_CREATE_PUK_POLICY);
        verifier.addString(id);
        verifier.addArray(pukValue);
        verifier.addByte(format);
        verifier.addShort(retryLimit);
        verifier.verify(mac);

        ///////////////////////////////////////////////////////////////////////////////////
        // Success, return PUK and updated session data
        ///////////////////////////////////////////////////////////////////////////////////
        SEPUKData sePukData = new SEPUKData();
        sePukData.provisioningState = unwrappedSessionKey.writeKey();
        sePukData.pukValue = decryptedPukValue;
        return sePukData;
    }
}

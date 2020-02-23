/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.Arrays;
import java.util.LinkedHashMap;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
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
    static final String SKS_VENDOR_NAME              = "WebPKI.org";
    static final String SKS_VENDOR_DESCRIPTION       = "SKS TEE/SE RI - SE Module";
    static final String SKS_UPDATE_URL               = null;  // Change here to test or disable
    static final boolean SKS_RSA_EXPONENT_SUPPORT    = false;
    static final short[] SKS_DEFAULT_RSA_SUPPORT     = {2048};
    static final int MAX_LENGTH_CRYPTO_DATA          = 16384;
    static final int MAX_LENGTH_EXTENSION_DATA       = 65536;

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
        byte algorithmIndex;

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

    static LinkedHashMap<String, Algorithm> supportedAlgorithms = new LinkedHashMap<>();

    static byte byteAlgorithmId;
    
    static Algorithm addAlgorithm(String uri, String jceName, int mask) {
        Algorithm alg = new Algorithm();
        alg.algorithmIndex = byteAlgorithmId++;
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

        addAlgorithm("https://webpki.github.io/sks/algorithm#aes.ecb.nopad",
                     "AES/ECB/NoPadding",
                     ALG_SYM_ENC | ALG_SYML_128 | ALG_SYML_192 | ALG_SYML_256 | ALG_AES_PAD);

        addAlgorithm("https://webpki.github.io/sks/algorithm#aes.cbc",
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
        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.es.pkcs1_5",
                     "RSA/ECB/PKCS1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.oaep.sha1",
                     "RSA/ECB/OAEPWithSHA-1AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY);

        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.oaep.sha256",
                     "RSA/ECB/OAEPWithSHA-256AndMGF1Padding",
                     ALG_ASYM_ENC | ALG_RSA_KEY | ALG_HASH_256);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Diffie-Hellman Key Agreement
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("https://webpki.github.io/sks/algorithm#ecdh.raw",
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

        addAlgorithm("https://webpki.github.io/sks/algorithm#rsa.pkcs1.none",
                     "NONEwithRSA",
                     ALG_ASYM_SGN | ALG_RSA_KEY);

        addAlgorithm("https://webpki.github.io/sks/algorithm#ecdsa.none",
                     "NONEwithECDSA",
                     ALG_ASYM_SGN | ALG_EC_KEY);

        //////////////////////////////////////////////////////////////////////////////////////
        //  Asymmetric Key Generation
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p256",
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

        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p384",
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

        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.nist.p521",
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

        addAlgorithm("https://webpki.github.io/sks/algorithm#ec.brainpool.p256r1",
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

        for (short rsa_size : SKS_DEFAULT_RSA_SUPPORT) {
            addAlgorithm("https://webpki.github.io/sks/algorithm#rsa" + rsa_size,
                    null, ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            if (SKS_RSA_EXPONENT_SUPPORT) {
                addAlgorithm("https://webpki.github.io/sks/algorithm#rsa" + rsa_size + ".exp",
                        null, ALG_KEY_PARM | ALG_RSA_KEY | ALG_KEY_GEN | rsa_size);
            }
        }

        //////////////////////////////////////////////////////////////////////////////////////
        //  Special Algorithms
        //////////////////////////////////////////////////////////////////////////////////////
        addAlgorithm(SecureKeyStore.ALGORITHM_SESSION_ATTEST_1, null, 0);

        addAlgorithm(SecureKeyStore.ALGORITHM_KEY_ATTEST_1, null, 0);

        addAlgorithm("https://webpki.github.io/sks/algorithm#none", null, ALG_NONE);

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

    static final byte[] INTEGRITY_MODIFIER = {'I', 'n', 't', 'e', 'g', 'r', 'i', 't', 'y'};

    static byte[] userKeyWrapperSecret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(USER_KEY_ENCRYPTION);
            userKeyWrapperSecret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] sessionKeyWrapperSecret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(SESSION_KEY_ENCRYPTION);
            sessionKeyWrapperSecret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] userKeyMacSecret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(INTEGRITY_MODIFIER);
            macBuilder.addVerbatim(USER_KEY_ENCRYPTION);
            userKeyMacSecret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static byte[] sessionKeyMacSecret;

    static {
        try {
            MacBuilder macBuilder = new MacBuilder(SE_MASTER_SECRET);
            macBuilder.addVerbatim(INTEGRITY_MODIFIER);
            macBuilder.addVerbatim(SESSION_KEY_ENCRYPTION);
            sessionKeyMacSecret = macBuilder.getResult();
        } catch (GeneralSecurityException e) {
            throw new RuntimeException(e);
        }
    }

    static final char[] ATTESTATION_KEY_PASSWORD = {'t', 'e', 's', 't', 'i', 'n', 'g'};

    static final String ATTESTATION_KEY_ALIAS = "mykey";

    static X509Certificate[] deviceCertificatePath;
    static PrivateKey attestationKey;

    static {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(SEReferenceImplementation.class.getResourceAsStream("attestationkeystore.jks"), ATTESTATION_KEY_PASSWORD);
            attestationKey = (PrivateKey)ks.getKey(ATTESTATION_KEY_ALIAS, ATTESTATION_KEY_PASSWORD);
            deviceCertificatePath = new X509Certificate[]{(X509Certificate) ks.getCertificate(ATTESTATION_KEY_ALIAS)};
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

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
        
        byte[] endorsedAlgorithms;

        boolean isRsa() {
            return privateKey instanceof RSAKey;
        }

        private byte[] createMAC(byte[] osInstanceKey) throws GeneralSecurityException {
            MacBuilder macBuilder = new MacBuilder(deriveKey(osInstanceKey, userKeyMacSecret));
            macBuilder.addBool(isExportable);
            macBuilder.addBool(isSymmetric);
            macBuilder.addArray(wrappedKey);
            macBuilder.addArray(sha256OfPublicKeyOrCertificate);
            macBuilder.addArray(endorsedAlgorithms);
            return macBuilder.getResult();
        }

        byte[] writeKey(byte[] osInstanceKey) throws IOException, GeneralSecurityException {
            ByteWriter byteWriter = new ByteWriter();
            byteWriter.writeArray(wrappedKey);
            byteWriter.writeBoolean(isSymmetric);
            byteWriter.writeBoolean(isExportable);
            byteWriter.writeArray(sha256OfPublicKeyOrCertificate);
            byteWriter.writeArray(endorsedAlgorithms);
            byteWriter.writeArray(createMAC(osInstanceKey));
            return byteWriter.getData();
        }

        void readKey(byte[] osInstanceKey, byte[] sealedKey) throws IOException, GeneralSecurityException {
            ByteReader byteReader = new ByteReader(sealedKey);
            wrappedKey = byteReader.getArray();
            isSymmetric = byteReader.readBoolean();
            isExportable = byteReader.readBoolean();
            sha256OfPublicKeyOrCertificate = byteReader.readArray(32);
            endorsedAlgorithms = byteReader.getArray();
            byte[] oldMac = byteReader.readArray(32);
            byteReader.checkEOF();
            byteReader.close();
            if (!Arrays.equals(oldMac, createMAC(osInstanceKey))) {
                throw new GeneralSecurityException("Sealed key MAC error");
            }
        }
    }

    static class UnwrappedSessionKey {
        byte[] sessionKey;

        byte[] wrappedSessionKey;

        short macSequenceCounter;

        short sessionKeyLimit;


        private byte[] createMAC(byte[] osInstanceKey) throws GeneralSecurityException {
            MacBuilder macBuilder = new MacBuilder(deriveKey(osInstanceKey, sessionKeyMacSecret));
            macBuilder.addArray(wrappedSessionKey);
            macBuilder.addShort(macSequenceCounter);
            macBuilder.addShort(sessionKeyLimit);
            return macBuilder.getResult();
        }
        
        public void readKey(byte[] osInstanceKey, byte[] provisioningState) 
        throws IOException, GeneralSecurityException {
            ByteReader byteReader = new ByteReader(provisioningState);
            wrappedSessionKey = byteReader.readArray(SecureKeyStore.AES_CBC_PKCS5_PADDING + 32);
            macSequenceCounter = byteReader.readShort();
            sessionKeyLimit = byteReader.readShort();
            byte[] oldMac = byteReader.readArray(32);
            byteReader.checkEOF();
            byteReader.close();
            if (!Arrays.equals(oldMac, createMAC(osInstanceKey))) {
                throw new GeneralSecurityException("Sealed session key MAC error");
            }
        }

        byte[] writeKey(byte[] osInstanceKey) throws IOException, GeneralSecurityException {
            ByteWriter byteWriter = new ByteWriter();
            byteWriter.writeArray(wrappedSessionKey);
            byteWriter.writeShort(macSequenceCounter);
            byteWriter.writeShort(sessionKeyLimit);
            byteWriter.writeArray(createMAC(osInstanceKey));
            return byteWriter.getData();
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

    static UnwrappedKey getUnwrappedKey(byte[] osInstanceKey, byte[] sealedKey)
    throws IOException, GeneralSecurityException {
        UnwrappedKey unwrappedKey = new UnwrappedKey();
        unwrappedKey.readKey(osInstanceKey, sealedKey);
        byte[] data = unwrappedKey.wrappedKey;
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        crypt.init(Cipher.DECRYPT_MODE, 
                   new SecretKeySpec(deriveKey(osInstanceKey, userKeyWrapperSecret), "AES"), 
                   new IvParameterSpec(data, 0, 16));
        byte[] rawKey = crypt.doFinal(data, 16, data.length - 16);
        if (unwrappedKey.isSymmetric) {
            unwrappedKey.symmetricKey = rawKey;
        } else {
            unwrappedKey.privateKey = raw2PrivateKey(rawKey);
        }
        return unwrappedKey;
    }

    static byte[] wrapKey(byte[] osInstanceKey, UnwrappedKey unwrappedKey, byte[] rawKey) 
    throws IOException, GeneralSecurityException {
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        crypt.init(Cipher.ENCRYPT_MODE, 
                   new SecretKeySpec(deriveKey(osInstanceKey, userKeyWrapperSecret), "AES"),
                   new IvParameterSpec(iv));
        unwrappedKey.wrappedKey = addArrays(iv, crypt.doFinal(rawKey));
        return unwrappedKey.writeKey(osInstanceKey);
    }

    static UnwrappedSessionKey getUnwrappedSessionKey(byte[] osInstanceKey, byte[] provisioningState) 
    throws IOException, GeneralSecurityException {
        UnwrappedSessionKey unwrappedSessionKey = new UnwrappedSessionKey();
        unwrappedSessionKey.readKey(osInstanceKey, provisioningState);
        byte[] data = unwrappedSessionKey.wrappedSessionKey;
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        crypt.init(Cipher.DECRYPT_MODE, 
                   new SecretKeySpec(deriveKey(osInstanceKey, sessionKeyWrapperSecret), "AES"), 
                   new IvParameterSpec(data, 0, 16));
        unwrappedSessionKey.sessionKey = crypt.doFinal(data, 16, data.length - 16);
        return unwrappedSessionKey;
    }

    static byte[] wrapSessionKey(byte[] osInstanceKey, 
                                 UnwrappedSessionKey unwrappedSessionKey,
                                 byte[] rawKey, 
                                 short sessionKeyLimit)
    throws IOException, GeneralSecurityException {
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        crypt.init(Cipher.ENCRYPT_MODE, 
                   new SecretKeySpec(deriveKey(osInstanceKey, sessionKeyWrapperSecret), "AES"), 
                   new IvParameterSpec(iv));
        unwrappedSessionKey.wrappedSessionKey = addArrays(iv, crypt.doFinal(rawKey));
        unwrappedSessionKey.sessionKeyLimit = sessionKeyLimit;
        return unwrappedSessionKey.writeKey(osInstanceKey);
    }

    static byte[] getDeviceID(boolean privacyEnabled) throws IOException, GeneralSecurityException {
        return privacyEnabled ? SecureKeyStore.KDF_ANONYMOUS : deviceCertificatePath[0].getEncoded();
    }

    static int getShort(byte[] buffer, int index) {
        return ((buffer[index++] << 8) & 0xFFFF) + (buffer[index] & 0xFF);
    }

    static void abort(String message) {
        throw new SKSException(message);
    }

    static void abort(String message, int option) {
        throw new SKSException(message, option);
    }

    static void abort(Exception e) {
        throw new SKSException(e, SKSException.ERROR_CRYPTO);
    }

    static void checkIDSyntax(String identifier, String symbolicName) {
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
            abort("Malformed \"" + symbolicName + "\" : " + identifier);
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

    static String checkEcKeyCompatibility(ECKey ecKey, String keyId) {
        Algorithm ecType = getEcType(ecKey);
        if (ecType != null) {
            return ecType.jceName;
        }
        abort("Unsupported EC key algorithm for: " + keyId);
        return null;
    }

    static void checkRsaKeyCompatibility(RSAPublicKey publicKey, String keyId) {

        if (!SKS_RSA_EXPONENT_SUPPORT && !publicKey.getPublicExponent().equals(RSAKeyGenParameterSpec.F4)) {
            abort("Unsupported RSA exponent value for: " + keyId);
        }
        int rsaKeySize = getRsaKeySize(publicKey);
        boolean found = false;
        for (short keySize : SKS_DEFAULT_RSA_SUPPORT) {
            if (keySize == rsaKeySize) {
                found = true;
                break;
            }
        }
        if (!found) {
            abort("Unsupported RSA key size " + rsaKeySize + " for: " + keyId);
        }
    }

    static void coreCompatibilityCheck(PublicKey publicKey, boolean rsaFlag, String id){
        if (rsaFlag ^ publicKey instanceof RSAPublicKey) {
            abort("RSA/EC mixup between public and private keys for: " + id);
        }
    }

    static int getRsaKeySize(RSAKey rsaKey) {
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

        void addString(String string) throws IOException {
            addArray(string.getBytes("UTF-8"));
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

        void verify(byte[] claimedMac) {
            if (!Arrays.equals(getResult(), claimedMac)) {
                abort("MAC error", SKSException.ERROR_MAC);
            }
        }
    }

    static class AttestationSignatureGenerator {
        SignatureWrapper signer;

        AttestationSignatureGenerator() throws IOException, GeneralSecurityException {
            signer = new SignatureWrapper(attestationKey instanceof RSAPrivateKey ? 
                                                                  "SHA256withRSA" : "SHA256withECDSA",
                                          attestationKey);
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

    static MacBuilder getMacBuilder(UnwrappedSessionKey unwrappedSessionKey, byte[] keyModifier) throws GeneralSecurityException {
        if (unwrappedSessionKey.sessionKeyLimit-- <= 0) {
            abort("\"SessionKeyLimit\" exceeded");
        }
        return new MacBuilder(addArrays(unwrappedSessionKey.sessionKey, keyModifier));
    }

    static MacBuilder getMacBuilderForMethodCall(UnwrappedSessionKey unwrappedSessionKey, byte[] method) throws GeneralSecurityException {
        short q = unwrappedSessionKey.macSequenceCounter++;
        return getMacBuilder(unwrappedSessionKey, addArrays(method, new byte[]{(byte) (q >>> 8), (byte) q}));
    }

    static MacBuilder getEECertMacBuilder(UnwrappedSessionKey unwrappedSessionKey,
                                          UnwrappedKey unwrappedKey,
                                          X509Certificate eeCertificate,
                                          byte[] method) throws GeneralSecurityException {
        byte[] binEe = eeCertificate.getEncoded();
        if (!Arrays.equals(unwrappedKey.sha256OfPublicKeyOrCertificate, getSHA256(binEe))) {
            throw new GeneralSecurityException("\"EECertificate\" Inconsistency test failed");
        }
        MacBuilder macBuilder = getMacBuilderForMethodCall(unwrappedSessionKey, method);
        macBuilder.addArray(binEe);
        return macBuilder;
    }

    static byte[] decrypt(UnwrappedSessionKey unwrappedSessionKey, byte[] data) throws GeneralSecurityException {
        byte[] key = getMacBuilder(unwrappedSessionKey,
                SecureKeyStore.ZERO_LENGTH_ARRAY).addVerbatim(SecureKeyStore.KDF_ENCRYPTION_KEY).getResult();
        Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
        crypt.init(Cipher.DECRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(data, 0, 16));
        return crypt.doFinal(data, 16, data.length - 16);
    }

    static boolean verifyKeyManagementKeyAuthorization(PublicKey keyManagementKey,
                                                       byte[] kmkKdf,
                                                       byte[] argument,
                                                       byte[] authorization) throws GeneralSecurityException {
        return new SignatureWrapper(keyManagementKey instanceof RSAPublicKey ? 
                                                             "SHA256WithRSA" : "SHA256WithECDSA",
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
                                       byte[] mac) throws IOException, GeneralSecurityException {
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

    static Algorithm getAlgorithm(String algorithm_uri) {
        Algorithm alg = supportedAlgorithms.get(algorithm_uri);
        if (alg == null) {
            abort("Unsupported algorithm: " + algorithm_uri, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    static void testSymmetricKey(String algorithm,
                                 byte[] symmetricKey,
                                 String keyId) {
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

    static Algorithm checkKeyAndAlgorithm(UnwrappedKey unwrappedKey, int keyHandle, String algorithm, int expectedType) {
        Algorithm alg = getAlgorithm(algorithm);
        if ((alg.mask & expectedType) == 0) {
            abort("Algorithm does not match operation: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        if (((alg.mask & (ALG_SYM_ENC | ALG_HMAC)) != 0) ^ unwrappedKey.isSymmetric) {
            abort((unwrappedKey.isSymmetric ? "S" : "As") + "ymmetric key #" + 
                  keyHandle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        if (unwrappedKey.isSymmetric) {
            testSymmetricKey(algorithm, unwrappedKey.symmetricKey, "#" + keyHandle);
        } else if (unwrappedKey.isRsa() ^ (alg.mask & ALG_RSA_KEY) != 0) {
            abort((unwrappedKey.isRsa() ? "RSA" : "EC") + " key #" + 
                  keyHandle + " is incompatible with: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        if (unwrappedKey.endorsedAlgorithms.length > 0) {
            for (byte endorsedAlgorithm : unwrappedKey.endorsedAlgorithms) {
                if (alg.algorithmIndex == endorsedAlgorithm) {
                    return alg;
                }
            }
            abort("Algorithm not endorsed: " + algorithm, SKSException.ERROR_ALGORITHM);
        }
        return alg;
    }

    public static SEVoidData testKeyAndAlgorithmCompliance(byte[] osInstanceKey,
                                                           byte[] sealedKey,
                                                           String algorithm,
                                                           String id) {
        SEVoidData seVoidData = new SEVoidData();
        try {
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
                        return seVoidData;
                    } else {
                        ///////////////////////////////////////////////////////////////////////////////////
                        // Asymmetric.  Check that algorithms match RSA or EC
                        ///////////////////////////////////////////////////////////////////////////////////
                        if (((alg.mask & ALG_RSA_KEY) == 0) ^ unwrappedKey.isRsa()) {
                            return seVoidData;
                        }
                    }
                }
                abort((unwrappedKey.isSymmetric ? "Symmetric" : unwrappedKey.isRsa() ? "RSA" : "EC") +
                        " key " + id + " does not match algorithm: " + algorithm);
            }
        } catch (Exception e) {
            seVoidData.setError(e);
        }
        return seVoidData;
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


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              getDeviceInfo                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEDeviceInfo getDeviceInfo() {
        SEDeviceInfo seDeviceInfo = new SEDeviceInfo();
        try {
            seDeviceInfo.apiLevel            = SecureKeyStore.SKS_API_LEVEL;
            seDeviceInfo.deviceType          = (byte) (DeviceInfo.LOCATION_EMBEDDED | DeviceInfo.TYPE_SOFTWARE);
            seDeviceInfo.updateUrl           = SKS_UPDATE_URL;
            seDeviceInfo.vendorName          = SKS_VENDOR_NAME;
            seDeviceInfo.vendorDescription   = SKS_VENDOR_DESCRIPTION;
            seDeviceInfo.certificatePath     = deviceCertificatePath;
            seDeviceInfo.supportedAlgorithms = supportedAlgorithms.keySet().toArray(new String[0]);
            seDeviceInfo.cryptoDataSize      = MAX_LENGTH_CRYPTO_DATA;
            seDeviceInfo.extensionDataSize   = MAX_LENGTH_EXTENSION_DATA;
        } catch (Exception e) {
            seDeviceInfo.setError(e);
        }
        return seDeviceInfo;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              checkKeyPair                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEVoidData checkKeyPair(byte[] osInstanceKey,
                                          byte[] sealedKey,
                                          PublicKey publicKey,
                                          String id) {
        SEVoidData seVoidData = new SEVoidData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Perform "sanity" checks
            ///////////////////////////////////////////////////////////////////////////////////
            coreCompatibilityCheck(publicKey, unwrappedKey.isRsa(), id);
            String signatureAlgorithm = unwrappedKey.isRsa() ? "NONEwithRSA" : "NONEwithECDSA";
            Signature sign = Signature.getInstance(signatureAlgorithm);
            sign.initSign(unwrappedKey.privateKey);
            sign.update(RSA_ENCRYPTION_OID);  // Any data could be used...
            byte[] signedData = sign.sign();
            Signature verify = Signature.getInstance(signatureAlgorithm);
            verify.initVerify(publicKey);
            verify.update(RSA_ENCRYPTION_OID);
            if (!verify.verify(signedData)) {
                abort("Public/private key mismatch for: " + id);
            }
      } catch (Exception e) {
            seVoidData.setError(e);
        }
        return seVoidData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                        executeAsymmetricDecrypt                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData executeAsymmetricDecrypt(byte[] osInstanceKey,
                                                           byte[] sealedKey,
                                                           int keyHandle,
                                                           String algorithm,
                                                           byte[] parameters,
                                                           byte[] data) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
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
            Cipher cipher = Cipher.getInstance(alg.jceName);
            if ((alg.mask & ALG_HASH_256) != 0) {
                cipher.init(Cipher.DECRYPT_MODE, unwrappedKey.privateKey,
                    new OAEPParameterSpec(
                        "SHA-256", "MGF1", MGF1ParameterSpec.SHA256, PSource.PSpecified.DEFAULT));
            } else {
                cipher.init(Cipher.DECRYPT_MODE, unwrappedKey.privateKey);
            }
            seByteArrayData.data = cipher.doFinal(data);
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            executeSignHash                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData executeSignHash(byte[] osInstanceKey,
                                                  byte[] sealedKey,
                                                  int keyHandle,
                                                  String algorithm,
                                                  byte[] parameters,
                                                  byte[] data) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
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
            if (unwrappedKey.isRsa() && hashLen > 0) {
                data = addArrays(alg.pkcs1DigestInfo, data);
            }
            seByteArrayData.data = new SignatureWrapper(alg.jceName, unwrappedKey.privateKey)
                    .update(data)
                    .sign();
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                               executeHMAC                                  //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData executeHMAC(byte[] osInstanceKey,
                                              byte[] sealedKey,
                                              int keyHandle,
                                              String algorithm,
                                              byte[] parameters,
                                              byte[] data) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
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
            Mac mac = Mac.getInstance(alg.jceName);
            mac.init(new SecretKeySpec(unwrappedKey.symmetricKey, "RAW"));
            seByteArrayData.data = mac.doFinal(data);
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                      executeSymmetricEncryption                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData executeSymmetricEncryption(byte[] osInstanceKey,
                                                             byte[] sealedKey,
                                                             int keyHandle,
                                                             String algorithm,
                                                             boolean mode,
                                                             byte[] parameters,
                                                             byte[] data) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
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
                abort("Data must be a multiple of 16 bytes for: " + algorithm + 
                      (mode ? " encryption" : " decryption"));
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, perform operation
            ///////////////////////////////////////////////////////////////////////////////////
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
            seByteArrayData.data = (mode && (alg.mask & ALG_IV_INT) != 0) ? addArrays(parameters, data) : data;
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         executeKeyAgreement                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData executeKeyAgreement(byte[] osInstanceKey,
                                                      byte[] sealedKey,
                                                      int keyHandle,
                                                      String algorithm,
                                                      byte[] parameters,
                                                      ECPublicKey publicKey) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
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
            checkEcKeyCompatibility(publicKey, "\"" + SecureKeyStore.VAR_PUBLIC_KEY + "\"");
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, perform operation
            ///////////////////////////////////////////////////////////////////////////////////
            KeyAgreement keyAgreement = KeyAgreement.getInstance(alg.jceName);
            keyAgreement.init(unwrappedKey.privateKey);
            keyAgreement.doPhase(publicKey, true);
            seByteArrayData.data = keyAgreement.generateSecret();
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                              unwrapKey                                     //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData unwrapKey(byte[] osInstanceKey, byte[] sealedKey) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
            if (unwrappedKey.isExportable) {
                seByteArrayData.data = unwrappedKey.isSymmetric ? 
                                      unwrappedKey.symmetricKey : unwrappedKey.privateKey.getEncoded();
            } else {
                throw new SKSException("TEE export violation attempt", SKSException.ERROR_NOT_ALLOWED);
            }
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey2                               //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData validateTargetKey2(byte[] osInstanceKey,
                                                     X509Certificate targetKeyEeCertificate,
                                                     int targetKeyHandle,
                                                     PublicKey keyManagementKey,
                                                     X509Certificate eeCertificate,
                                                     byte[] sealedKey,
                                                     boolean privacyEnabled,
                                                     byte[] method,
                                                     byte[] authorization,
                                                     byte[] provisioningState,
                                                     byte[] mac) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey, 
                                                                             provisioningState);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the new key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
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
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return updated session data
            ///////////////////////////////////////////////////////////////////////////////////
            seByteArrayData.data = unwrappedSessionKey.writeKey(osInstanceKey);
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                           validateTargetKey                                //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData validateTargetKey(byte[] osInstanceKey,
                                                    X509Certificate targetKeyEeCertificate,
                                                    int targetKeyHandle,
                                                    PublicKey keyManagementKey,
                                                    boolean privacyEnabled,
                                                    byte[] method,
                                                    byte[] authorization,
                                                    byte[] provisioningState,
                                                    byte[] mac) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
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
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return updated session data
            ///////////////////////////////////////////////////////////////////////////////////
            seByteArrayData.data = unwrappedSessionKey.writeKey(osInstanceKey);
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                     validateRollOverAuthorization                          //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEBooleanData validateRollOverAuthorization(PublicKey newKeyManagementKey,
                                                              PublicKey oldKeyManagementKey,
                                                              byte[] authorization) {
        SEBooleanData seBooleanData = new SEBooleanData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify KMK signature
            ///////////////////////////////////////////////////////////////////////////////////
            seBooleanData.bool =
                    verifyKeyManagementKeyAuthorization(oldKeyManagementKey,
                                                        SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                                                        newKeyManagementKey.getEncoded(),
                                                        authorization);
        } catch (Exception e) {
            seBooleanData.setError(e);
        }
        return seBooleanData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                         closeProvisioningAttest                            //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData closeProvisioningAttest(byte[] osInstanceKey,
                                                          byte[] provisioningState,
                                                          String serverSessionId,
                                                          String clientSessionId,
                                                          String issuerUri,
                                                          byte[] nonce,
                                                          byte[] mac) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
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
            seByteArrayData.data = closeAttestation.getResult();
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
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
                                                            short sessionLifeTime,
                                                            short sessionKeyLimit,
                                                            byte[] serverCertificate) {
        SEProvisioningData seProvisioningData = new SEProvisioningData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Check provisioning session algorithm compatibility
            ///////////////////////////////////////////////////////////////////////////////////
            if (!sessionKeyAlgorithm.equals(SecureKeyStore.ALGORITHM_SESSION_ATTEST_1)) {
                abort("Unknown \"" + SecureKeyStore.VAR_SESSION_KEY_ALGORITHM + 
                      "\" : " + sessionKeyAlgorithm);
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
            String jceName = checkEcKeyCompatibility(serverEphemeralKey,
                                                     "\"" + SecureKeyStore.VAR_SERVER_EPHEMERAL_KEY + "\"");
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check optional key management key compatibility
            ///////////////////////////////////////////////////////////////////////////////////
            if (keyManagementKey != null) {
                if (keyManagementKey instanceof RSAPublicKey) {
                    checkRsaKeyCompatibility((RSAPublicKey) keyManagementKey,
                                             "\"" + SecureKeyStore.VAR_KEY_MANAGEMENT_KEY + "\"");
                } else {
                    checkEcKeyCompatibility((ECPublicKey) keyManagementKey, 
                                            "\"" + SecureKeyStore.VAR_KEY_MANAGEMENT_KEY + "\"");
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
                ska.addArray(keyManagementKey == null ? 
                     SecureKeyStore.ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                ska.addInt(clientTime);
                ska.addShort(sessionLifeTime);
                ska.addShort(sessionKeyLimit);
                ska.addArray(serverCertificate);
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
                pka.addArray(keyManagementKey == null ? 
                     SecureKeyStore.ZERO_LENGTH_ARRAY : keyManagementKey.getEncoded());
                pka.addInt(clientTime);
                pka.addShort(sessionLifeTime);
                pka.addShort(sessionKeyLimit);
                pka.addArray(serverCertificate);
                seProvisioningData.attestation = pka.getResult();
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Create the wrapped session key and associated data
            ///////////////////////////////////////////////////////////////////////////////////
            seProvisioningData.provisioningState = wrapSessionKey(osInstanceKey, 
                                                                  new UnwrappedSessionKey(), 
                                                                  sessionKey, 
                                                                  sessionKeyLimit);
            seProvisioningData.clientSessionId = clientSessionId;
            seProvisioningData.clientEphemeralKey = clientEphemeralKey;
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return provisioning session data including sealed session object
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            seProvisioningData.setError(e);
        }
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
                                                             byte[] mac) {
        SEPrivateKeyData sePrivateKeyData = new SEPrivateKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
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
            sePrivateKeyData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            sePrivateKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, decryptedPrivateKey);
            PublicKey publicKey = eeCertificate.getPublicKey();
            boolean rsaFlag = decodedPrivateKey instanceof RSAKey;
            coreCompatibilityCheck(publicKey, rsaFlag, id);
            if (rsaFlag) {
                // https://stackoverflow.com/questions/24121801/how-to-verify-if-the-private-key-matches-with-the-certificate
                if (!(((RSAPublicKey)publicKey).getModulus()
                            .equals(((RSAPrivateKey)decodedPrivateKey).getModulus()) &&
                      BigInteger.valueOf(2).modPow(((RSAPublicKey)publicKey).getPublicExponent()
                                .multiply(((RSAPrivateKey)decodedPrivateKey).getPrivateExponent())
                                .subtract(BigInteger.ONE),((RSAPublicKey) publicKey).getModulus())
                            .equals(BigInteger.ONE))) {
                    abort("Imported RSA key does not match certificate for: " + id);
                }
            } else {
                checkEcKeyCompatibility((ECPrivateKey) decodedPrivateKey, id);
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return updated key and session data
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            sePrivateKeyData.setError(e);
        }
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
                                                                 byte[] mac) {
        SESymmetricKeyData seSymmetricKeyData = new SESymmetricKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check for key length errors
            ///////////////////////////////////////////////////////////////////////////////////
            if (encryptedKey.length > (SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + 
                                       SecureKeyStore.AES_CBC_PKCS5_PADDING)) {
                abort("Symmetric key: " + id + " exceeds " + 
                      SecureKeyStore.MAX_LENGTH_SYMMETRIC_KEY + " bytes");
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
            seSymmetricKeyData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            seSymmetricKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, rawKey);
            seSymmetricKeyData.symmetricKeyLength = (short) rawKey.length;
        
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return updated key and session data
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            seSymmetricKeyData.setError(e);
        }
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
                                                        byte[] mac) {
        SEExtensionData seExtensionData = new SEExtensionData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use (verify integrity only in this case)
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
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
            seExtensionData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            seExtensionData.extensionData = subType == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION ?
                    decrypt(unwrappedSessionKey, extensionData) : extensionData.clone();
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return extension data and updated session data
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            seExtensionData.setError(e);
        }
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
                                                                byte[] mac) {
        SECertificateData seCertificateData = new SECertificateData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Unwrap the key to use
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = getUnwrappedKey(osInstanceKey, sealedKey);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify key consistency 
            ///////////////////////////////////////////////////////////////////////////////////
            byte[] binPublicKey = publicKey.getEncoded();
            if (!Arrays.equals(unwrappedKey.sha256OfPublicKeyOrCertificate, getSHA256(binPublicKey))) {
                throw new GeneralSecurityException("\"" + SecureKeyStore.VAR_PUBLIC_KEY + 
                                                   "\" inconsistency test failed");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey, 
                                                             SecureKeyStore.METHOD_SET_CERTIFICATE_PATH);
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
            // Check key material for SKS compliance
            ///////////////////////////////////////////////////////////////////////////////////
            PublicKey certPublicKey = certificatePath[0].getPublicKey();
            if (certPublicKey instanceof RSAPublicKey) {
                checkRsaKeyCompatibility((RSAPublicKey) certPublicKey, id);
            } else {
                checkEcKeyCompatibility((ECPublicKey) certPublicKey, id);
            }
            
            ///////////////////////////////////////////////////////////////////////////////////
            // Update the sealed key with the certificate link
            ///////////////////////////////////////////////////////////////////////////////////
            unwrappedKey.sha256OfPublicKeyOrCertificate = getSHA256(certificatePath[0].getEncoded());
            seCertificateData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            seCertificateData.sealedKey = 
                    wrapKey(osInstanceKey, unwrappedKey, unwrappedKey.privateKey.getEncoded());
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return updated key and session data
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            seCertificateData.setError(e);
        }
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
                                          byte[] mac) {
        SEKeyData seKeyData = new SEKeyData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Validate input as much as possible
            ///////////////////////////////////////////////////////////////////////////////////
            if (!keyEntryAlgorithm.equals(SecureKeyStore.ALGORITHM_KEY_ATTEST_1)) {
                abort("Unknown \"" + SecureKeyStore.VAR_KEY_ENTRY_ALGORITHM + "\" : " +
                      keyEntryAlgorithm, SKSException.ERROR_ALGORITHM);
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
                abort((keyParameters == null ? "Missing" : "Unexpected") + " \"" + 
                      SecureKeyStore.VAR_KEY_PARAMETERS + "\"");
            }
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey,
                                                             SecureKeyStore.METHOD_CREATE_KEY_ENTRY);
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
            ByteArrayOutputStream endorsedAlgorithmIndices = new ByteArrayOutputStream();
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
                endorsedAlgorithmIndices.write(alg.algorithmIndex);
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
                        abort("\"" + SecureKeyStore.VAR_KEY_PARAMETERS + 
                              "\" length error: " + keyParameters.length);
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
            SecureRandom secure_random = serverSeed.length == 0 ? 
                                             new SecureRandom() : new SecureRandom(serverSeed);
            KeyPairGenerator kpg = 
                    KeyPairGenerator.getInstance(algPar_spec instanceof RSAKeyGenParameterSpec ? 
                                                                                         "RSA" : "EC");
            kpg.initialize(algPar_spec, secure_random);
            KeyPair keyPair = kpg.generateKeyPair();
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Create key attest
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder cka = getMacBuilderForMethodCall(unwrappedSessionKey, 
                                                        SecureKeyStore.KDF_DEVICE_ATTESTATION);
            cka.addArray(publicKey.getEncoded());
            cka.addArray(mac);
            byte[] attestation = cka.getResult();
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Finally, create the key return data
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedKey unwrappedKey = new UnwrappedKey();
            unwrappedKey.isExportable = 
                    exportProtection != SecureKeyStore.EXPORT_DELETE_PROTECTION_NOT_ALLOWED;
            unwrappedKey.sha256OfPublicKeyOrCertificate = getSHA256(publicKey.getEncoded());
            unwrappedKey.endorsedAlgorithms = endorsedAlgorithmIndices.toByteArray();
            seKeyData.sealedKey = wrapKey(osInstanceKey, unwrappedKey, privateKey.getEncoded());
            seKeyData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            seKeyData.attestation = attestation;
            seKeyData.publicKey = publicKey;
            seKeyData.decryptedPinValue = decryptedPinValue;
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return key data and updated session data
            ///////////////////////////////////////////////////////////////////////////////////
        } catch (Exception e) {
            seKeyData.setError(e);
        }
        return seKeyData;
    }


    ////////////////////////////////////////////////////////////////////////////////
    //                                                                            //
    //                            verifyPINPolicy                                 //
    //                                                                            //
    ////////////////////////////////////////////////////////////////////////////////
    public static SEByteArrayData verifyPINPolicy(byte[] osInstanceKey,
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
                                                  byte[] mac) {
        SEByteArrayData seByteArrayData = new SEByteArrayData();
        try {
            ///////////////////////////////////////////////////////////////////////////////////
            // Retrieve session key
            ///////////////////////////////////////////////////////////////////////////////////
            UnwrappedSessionKey unwrappedSessionKey = getUnwrappedSessionKey(osInstanceKey,
                                                                             provisioningState);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Check ID syntax
            ///////////////////////////////////////////////////////////////////////////////////
            checkIDSyntax(id, SecureKeyStore.VAR_ID);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Verify incoming MAC
            ///////////////////////////////////////////////////////////////////////////////////
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey,
                                                             SecureKeyStore.METHOD_CREATE_PIN_POLICY);
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
            seByteArrayData.data = unwrappedSessionKey.writeKey(osInstanceKey);
        } catch (Exception e) {
            seByteArrayData.setError(e);
        }
        return seByteArrayData;
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
                                        byte[] mac) {
        SEPUKData sePukData = new SEPUKData();
        try {
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
            MacBuilder verifier = getMacBuilderForMethodCall(unwrappedSessionKey,
                                                             SecureKeyStore.METHOD_CREATE_PUK_POLICY);
            verifier.addString(id);
            verifier.addArray(pukValue);
            verifier.addByte(format);
            verifier.addShort(retryLimit);
            verifier.verify(mac);
    
            ///////////////////////////////////////////////////////////////////////////////////
            // Success, return PUK and updated session data
            ///////////////////////////////////////////////////////////////////////////////////
            sePukData.provisioningState = unwrappedSessionKey.writeKey(osInstanceKey);
            sePukData.pukValue = decryptedPukValue;
        } catch (Exception e) {
            sePukData.setError(e);
        }
        return sePukData;
    }
}

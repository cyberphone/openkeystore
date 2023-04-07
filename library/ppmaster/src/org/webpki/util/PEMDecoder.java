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
package org.webpki.util;

import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPrivateCrtKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import java.util.ArrayList;

import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.DerDecoder;
import org.webpki.asn1.ParseUtil;

import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.OkpSupport;
import org.webpki.crypto.KeyAlgorithms;

/**
 * Functions for decoding PEM files.
 * 
#if BOUNCYCASTLE
 * Source configured for the BouncyCastle provider.
#else 
 * Source configured for the default provider.
#endif
 */
public class PEMDecoder {
    private PEMDecoder() {
    }  // No instantiation please

 
    static PublicKey ecPublicKeyFromPKCS8(byte[] pkcs8) throws IOException, 
                                                               GeneralSecurityException {
        ASN1Sequence seq = ParseUtil.sequence(DerDecoder.decode(pkcs8), 3);
        String oid = ParseUtil.oid(ParseUtil.sequence(seq.get(1), 2).get(1)).oid();
        seq = ParseUtil.sequence(DerDecoder.decode(ParseUtil.octet(seq.get(2))));
        byte[] publicKey;
        try {
            publicKey = ParseUtil.bitstring(ParseUtil.singleContext(seq.get(seq.size() -1), 1));
        } catch (Exception e) {
            throw new GeneralSecurityException(
                    "This implementation requires PKCS8 with public key attribute");
        }
        int length = (publicKey.length - 1) / 2;
        byte[] parm = new byte[length];
        System.arraycopy(publicKey, 1, parm, 0, length);
        BigInteger x = new BigInteger(1, parm);
        System.arraycopy(publicKey, 1 + length, parm, 0, length);
        BigInteger y = new BigInteger(1, parm);
        for (KeyAlgorithms ka : KeyAlgorithms.values()) {
            if (oid.equals(ka.getECDomainOID())) {
                if (oid.equals(ka.getECDomainOID())) {
                    ECPoint w = new ECPoint(x, y);
                    return KeyFactory.getInstance("EC").generatePublic(
                            new ECPublicKeySpec(w, ka.getECParameterSpec()));
                }
            }
        }
        throw new IOException("Failed creating EC public key from private key");
    }
    
    static PublicKey okpPublicKeyFromPKCS8(byte[] pkcs8) throws IOException,
                                                                GeneralSecurityException {
        ASN1Sequence seq = ParseUtil.sequence(DerDecoder.decode(pkcs8));
        KeyAlgorithms keyAlgorithm = 
                getKeyAlgorithm(ParseUtil.oid(ParseUtil.sequence(seq.get(1)).get(0)).oid());
        byte[] content;
        try {
            content = ParseUtil.simpleContext(seq.get(seq.size() - 1), 1).encodeContent();
        } catch (Exception e) {
            throw new GeneralSecurityException(
                    "This implementation requires a public key attribute (RFC8410)");
        }
        if (content[0] != 0) {
            throw new GeneralSecurityException(
                    "Missing leading 0 in public key attribute (RFC8410)");
        }
        byte[] publicKey = new byte[content.length - 1];
        System.arraycopy(content, 1, publicKey, 0, publicKey.length);
        return OkpSupport.raw2PublicKey(publicKey, keyAlgorithm);

    }
    
    private static byte[] getPrivateKeyBlob(byte[] pemBlob) throws IOException {
        return decodePemObject(pemBlob, "PRIVATE KEY");
    }
    
    private static PrivateKey getPrivateKeyFromPKCS8(byte[] pkcs8)
    throws IOException, GeneralSecurityException {
        PrivateKey privateKey = getKeyFactory(ParseUtil.sequence(DerDecoder.decode(pkcs8)).get(1))
                .generatePrivate(new PKCS8EncodedKeySpec(pkcs8));
        // This is for getting the identical representation to JWK decoding
        if (privateKey instanceof ECKey) {
            return KeyFactory.getInstance("EC")
                    .generatePrivate(new ECPrivateKeySpec(((ECPrivateKey)privateKey).getS(),
                                                          ((ECPrivateKey)privateKey).getParams()));
        }
        if (privateKey instanceof RSAKey) {
            return privateKey;
        }
        KeyAlgorithms keyAlgorithm = OkpSupport.getKeyAlgorithm(privateKey);
        return OkpSupport.raw2PrivateKey(OkpSupport.private2RawKey(privateKey, 
                                                                         keyAlgorithm), 
                                            keyAlgorithm);
    }

    public static KeyPair getKeyPair(byte[] pemBlob) throws IOException, GeneralSecurityException {
        byte[] pkcs8 = getPrivateKeyBlob(pemBlob);
        PrivateKey privateKey =  getPrivateKeyFromPKCS8(pkcs8);
        if (privateKey instanceof ECKey) {
            return new KeyPair(ecPublicKeyFromPKCS8(pkcs8), privateKey);
        }
        if (privateKey instanceof RSAKey) {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            RSAPrivateCrtKey privk = (RSAPrivateCrtKey)privateKey;
            return new KeyPair(keyFactory.generatePublic(
                new RSAPublicKeySpec(privk.getModulus(), privk.getPublicExponent())), privateKey);
        }
        return new KeyPair(okpPublicKeyFromPKCS8(pkcs8), privateKey);
    }
    
    static KeyAlgorithms getKeyAlgorithm(String oid) throws IOException {
        for (KeyAlgorithms keyAlgorithm : KeyAlgorithms.values()) {
            if (oid.equals(keyAlgorithm.getECDomainOID())) {
                return keyAlgorithm;
            }
        }
        throw new IOException("Did not find OID: " + oid);
    }

    private static KeyFactory getKeyFactory(BaseASN1Object object) 
    throws IOException, GeneralSecurityException {
        String oid = ParseUtil.oid(ParseUtil.sequence(object).get(0)).oid();
        if (oid.startsWith("1.3.101.11")) {
//#if BOUNCYCASTLE
            return KeyFactory.getInstance(getKeyAlgorithm(oid).getJceName(), "BC");
//#else
            return KeyFactory.getInstance(getKeyAlgorithm(oid).getJceName());
//#endif
        }
        return KeyFactory.getInstance(oid.equals("1.2.840.113549.1.1.1") ? "RSA" : "EC");
    }

    public static PrivateKey getPrivateKey(byte[] pemBlob) throws IOException, 
                                                                  GeneralSecurityException {
        return getPrivateKeyFromPKCS8(getPrivateKeyBlob(pemBlob)); 
    }
    
    public static PublicKey getPublicKey(byte[] pemBlob) throws IOException, 
                                                                GeneralSecurityException {
        byte[] publicKeyBlob = decodePemObject(pemBlob, "PUBLIC KEY");
        return getKeyFactory(ParseUtil.sequence(DerDecoder.decode(publicKeyBlob)).get(0))
                .generatePublic(new X509EncodedKeySpec(publicKeyBlob)); 
    }

    public static X509Certificate[] getCertificatePath(byte[] pemBlob) 
            throws IOException, GeneralSecurityException {
        return CertificateUtil.getSortedPathFromBlobs(
                decodePemObjects(pemBlob, "CERTIFICATE"));
    }

    public static KeyStore getKeyStore(byte[] pemBlob, String alias, String password)
            throws IOException, GeneralSecurityException {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, password.toCharArray());
        keyStore.setKeyEntry(alias,
                             getPrivateKey(pemBlob),
                             password.toCharArray(),
                             getCertificatePath(pemBlob));
        return keyStore;
    }

    public static X509Certificate getRootCertificate(byte[] pemBlob) 
    throws IOException, GeneralSecurityException {
        X509Certificate[] certPath = getCertificatePath(pemBlob);
        return certPath[certPath.length - 1];
    }

    private static ArrayList<byte[]> decodePemObjects(byte[]pemBlob, 
                                                      String itemType) throws IOException {
        String pemString = new String(pemBlob, "utf-8");
        String header = "-----BEGIN " + itemType + "-----";
        String footer = "-----END "   + itemType + "-----";
        ArrayList<byte[]> objects = new ArrayList<>();
        int start = 0;
        while (true) {
            start = pemString.indexOf(header, start);
            if (start < 0) {
                if (objects.isEmpty()) {
                    throw new IOException("Didn't find any: " + header);
                }
                break;
            }
            int end = pemString.indexOf(footer, start);
            if (end < 0) throw new IOException("Expected to find: " + footer);
            objects.add(Base64.decode(pemString.substring(start + header.length(), end)));
            start = end + footer.length();
        }
        return objects;
    }
    
    private static byte[] decodePemObject(byte[]pemBlob, String itemType) throws IOException {
        ArrayList<byte[]> objects = decodePemObjects(pemBlob, itemType);
        if (objects.size() != 1) {
            throw new IOException("Only expected one: " + itemType);
        }
        return objects.get(0);
    }
}

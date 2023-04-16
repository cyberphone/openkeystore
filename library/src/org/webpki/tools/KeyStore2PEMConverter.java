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
package org.webpki.tools;

import java.io.ByteArrayOutputStream;

import java.util.Enumeration;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import java.security.interfaces.ECKey;
import java.security.interfaces.RSAKey;

import org.webpki.asn1.ASN1Sequence;
import org.webpki.asn1.BaseASN1Object;
import org.webpki.asn1.CompositeContextSpecific;
import org.webpki.asn1.ASN1BitString;
import org.webpki.asn1.ASN1Integer;
import org.webpki.asn1.ASN1ObjectID;
import org.webpki.asn1.ASN1OctetString;
import org.webpki.asn1.SimpleContextSpecific;

import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.OkpSupport;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.util.IO;
import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;
import org.webpki.util.UTF8;

public class KeyStore2PEMConverter {
    
    public KeyStore2PEMConverter() {
    }
    
    static String EC_PUBLIC_KEY_OID = "1.2.840.10045.2.1";
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    boolean next;
    
    public byte[] getData() {
        return baos.toByteArray();
    }
    
    public void writePublicKey(PublicKey publicKey) throws Exception {
        writeObject("PUBLIC KEY", publicKey.getEncoded());
    }
    
    public void writePrivateKey(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        byte[] encoded;
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(privateKey);
        if (privateKey instanceof RSAKey) {
            encoded = privateKey.getEncoded();
        } else if (privateKey instanceof ECKey) {
            JSONObjectReader jwk = JSONParser.parse(new KeyStore2JWKConverter()
                    .writePrivateKey(privateKey, publicKey));
            encoded = new ASN1Sequence(new BaseASN1Object[] {
                new ASN1Integer(0),
                new ASN1Sequence(new BaseASN1Object[] {
                        new ASN1ObjectID(EC_PUBLIC_KEY_OID),
                        new ASN1ObjectID(keyAlgorithm.getECDomainOID())}),
                new ASN1OctetString(new ASN1Sequence(new BaseASN1Object[] {
                        new ASN1Integer(1),
                        new ASN1OctetString(jwk.getBinary("d")),
                        new CompositeContextSpecific(1, 
                                new ASN1BitString(
                      ArrayUtil.add(new byte[] {4},  
                                    ArrayUtil.add(jwk.getBinary("x"), jwk.getBinary("y")))))
                }).encode())
            }).encode();
        } else {
            encoded = new ASN1Sequence(new BaseASN1Object[] {
                new ASN1Integer(1),
                new ASN1Sequence(new ASN1ObjectID(keyAlgorithm.getECDomainOID())),
                new ASN1OctetString(new ASN1OctetString(
                        OkpSupport.private2RawKey(privateKey, keyAlgorithm)).encode()),
                new SimpleContextSpecific(1, 
                        ArrayUtil.add(new byte[] {0},  // BITSTRING unused bits 
                                      OkpSupport.public2RawKey(publicKey, keyAlgorithm)))
            }).encode();
        }
        writeObject("PRIVATE KEY", encoded);
    }
    
    public void writeCertificate(X509Certificate certificate) throws Exception {
        writeObject("CERTIFICATE", certificate.getEncoded());
    }

    private void writeObject(String string, byte[] encoded) throws Exception {
        if (next) {
            baos.write((byte)'\n');
        }
        next = true;
        baos.write(UTF8.encode("-----BEGIN " + string + "-----\n"));
        baos.write(UTF8.encode(Base64.mimeEncode(encoded)));
        baos.write(UTF8.encode("\n-----END " + string + "-----\n"));
    }
    
    private static void fail() {
        System.out.println(KeyStore2PEMConverter.class.getName() + "  keystore-file password PEM-file qualifier\n" +
                "   qualifier = [public private certpath trust]");
        System.exit(3);
    }

    public static void main(String argv[]) throws Exception {
        if (argv.length < 4) {
            fail();
        }
        boolean privateKeyFlag = false;
        boolean publicKeyFlag = false;
        boolean certificatePathFlag = false;
        boolean trustFlag = false;
        for (int i = 3; i < argv.length; i++) {
            if (argv[i].equals("public")) {
                publicKeyFlag = true;
            } else if (argv[i].equals("private")) {
                privateKeyFlag = true;
            } else if (argv[i].equals("certpath")) {
                certificatePathFlag = true;
            } else if (argv[i].equals("trust")) {
                trustFlag = true;
            } else {
                fail();
            }
        }
        CustomCryptoProvider.conditionalLoad(true);
        KeyStore ks = KeyStoreReader.loadKeyStore(argv[0], argv[1]);
        KeyStore2PEMConverter converter = new KeyStore2PEMConverter();
        Enumeration<String> aliases = ks.aliases();
        while (aliases.hasMoreElements()) {
            String alias = aliases.nextElement();
            if (ks.isKeyEntry(alias)) {
                PublicKey publicKey = ks.getCertificateChain(alias)[0].getPublicKey();
                if (privateKeyFlag) {
                    converter.writePrivateKey((PrivateKey)ks.getKey(alias, argv[1].toCharArray()),
                                              publicKey);
                }
                if (certificatePathFlag) { 
                    for (Certificate certificate : ks.getCertificateChain(alias)) {
                        converter.writeCertificate((X509Certificate)certificate);
                    }
                }
                if (publicKeyFlag) {
                    converter.writePublicKey(publicKey);
                }
            } else if (ks.isCertificateEntry(alias)) {
                if (trustFlag) {
                    converter.writeCertificate((X509Certificate)ks.getCertificate(alias));
                }
            } else {
                throw new Exception("Bad KS");
            }
        }
        IO.writeFile(argv[2], converter.getData());
    }
}

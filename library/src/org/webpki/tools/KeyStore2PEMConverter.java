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
package org.webpki.tools;

import java.io.ByteArrayOutputStream;

import java.util.Enumeration;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.webpki.crypto.KeyStoreReader;
import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.util.ArrayUtil;
import org.webpki.util.Base64;

public class KeyStore2PEMConverter {
    
    public KeyStore2PEMConverter() {
    }
    
    ByteArrayOutputStream baos = new ByteArrayOutputStream();
    
    boolean next;
    
    public byte[] getData() {
        return baos.toByteArray();
    }
    
    public void writePublicKey(PublicKey publicKey) throws Exception {
        writeObject("PUBLIC KEY", publicKey.getEncoded());
    }
    
    public void writePrivateKey(PrivateKey privateKey) throws Exception {
        writeObject("PRIVATE KEY", privateKey.getEncoded());
    }
    
    public void writeCertificate(X509Certificate certificate) throws Exception {
        writeObject("CERTIFICATE", certificate.getEncoded());
    }

    private void writeObject(String string, byte[] encoded) throws Exception {
        if (next) {
            baos.write((byte)'\n');
        }
        next = true;
        baos.write(("-----BEGIN " + string + "-----\n").getBytes("UTF-8"));
        baos.write(new Base64().getBase64BinaryFromBinary(encoded));
        baos.write(("\n-----END " + string + "-----\n").getBytes("UTF-8"));
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
                if (privateKeyFlag) {
                    converter.writePrivateKey((PrivateKey)ks.getKey(alias, argv[1].toCharArray()));
                }
                if (certificatePathFlag) { 
                    for (Certificate certificate : ks.getCertificateChain(alias)) {
                        converter.writeCertificate((X509Certificate)certificate);
                    }
                }
                if (publicKeyFlag) {
                    converter.writePublicKey(ks.getCertificateChain(alias)[0].getPublicKey());
                }
            } else if (ks.isCertificateEntry(alias)) {
                if (trustFlag) {
                    converter.writeCertificate((X509Certificate)ks.getCertificate(alias));
                }
            } else {
                throw new Exception("Bad KS");
            }
        }
        ArrayUtil.writeFile(argv[2], converter.getData());
    }
}

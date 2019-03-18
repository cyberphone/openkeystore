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
package org.webpki.crypto;

import java.io.IOException;

import java.util.Enumeration;

import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.KeyStore;
import java.security.PrivateKey;

import java.security.GeneralSecurityException;

/**
 * Sign data using the KeyStore interface.
 */
public class KeyStoreSigner implements SignerInterface, CertificateSelectorSpi {

    private PrivateKey privateKey;

    private KeyStore signerCertKeystore;

    private AuthorityInfoAccessCAIssuersSpi aiaCaissuerHandler;

    private String keyAlias;

    private boolean extendedCertpath;

    private boolean ecdsaDerEncoded;


    private KeyStoreSigner testKey(String keyAlias) throws IOException, GeneralSecurityException {
        if (!signerCertKeystore.isKeyEntry(keyAlias)) {
            throw new IOException("Specified certficate does not have a private key: " + keyAlias);
        }
        return this;
    }


    private X509Certificate[] getCertPath(String keyAlias, boolean pathExpansion) throws IOException, GeneralSecurityException {
        testKey(keyAlias);
        Certificate[] cp = signerCertKeystore.getCertificateChain(keyAlias);
        X509Certificate[] certificatePath = new X509Certificate[cp.length];
        for (int q = 0; q < cp.length; q++) {
            certificatePath[q] = (X509Certificate) cp[q];
        }
        if (pathExpansion && aiaCaissuerHandler != null) {
            return aiaCaissuerHandler.getUpdatedPath(certificatePath);
        }
        return certificatePath;
    }


    public CertificateSelection getCertificateSelection(CertificateFilter[] cfs) throws IOException {
        boolean path_expansion = false;
        for (CertificateFilter cf : cfs) {
            if (cf.needsPathExpansion()) {
                path_expansion = true;
                break;
            }
        }
        CertificateSelection cs = new CertificateSelection(this);
        try {
            Enumeration<String> aliases = signerCertKeystore.aliases();
            while (aliases.hasMoreElements()) {
                String new_key = aliases.nextElement();
                if (signerCertKeystore.isKeyEntry(new_key)) {
                    X509Certificate[] curr_path = getCertPath(new_key, path_expansion);
                    if (cfs.length == 0) {
                        cs.addEntry(new_key, curr_path[0]);
                        continue;
                    }
                    for (CertificateFilter cf : cfs) {
                        if (cf.matches(curr_path)) {
                            cs.addEntry(new_key, curr_path[0]);
                            break;  // No need to test other filters for this key; it is already selected
                        }
                    }
                }
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
        return cs;
    }


    @Override
    public X509Certificate[] getCertificatePath() throws IOException {
        try {
            X509Certificate[] path = getCertPath(keyAlias, true);
            return extendedCertpath ? path : new X509Certificate[]{path[0]};
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
    }


    public KeyStoreSigner setECDSASignatureEncoding(boolean derEncoded) {
        ecdsaDerEncoded = derEncoded;
        return this;
    }


    public KeyStoreSigner setAuthorityInfoAccessCAIssuersHandler(AuthorityInfoAccessCAIssuersSpi aiaCaissuerHandler) {
        this.aiaCaissuerHandler = aiaCaissuerHandler;
        return this;
    }


    @Override
    public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
        try {
            return new SignatureWrapper(algorithm, privateKey)
                .setEcdsaSignatureEncoding(ecdsaDerEncoded)
                .update(data)
                .sign();
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    public KeyStoreSigner(KeyStore signerCertKeystore, KeyContainerTypes containerType) {
        this.signerCertKeystore = signerCertKeystore;
    }


    public KeyStoreSigner setKey(String inKeyAlias, String password) throws IOException {
        keyAlias = inKeyAlias;
        try {
            if (keyAlias == null) {
                // Search for signer certificate/key:
                Enumeration<String> aliases = signerCertKeystore.aliases();

                while (aliases.hasMoreElements()) {
                    String new_key = aliases.nextElement();
                    if (signerCertKeystore.isKeyEntry(new_key)) {
                        if (keyAlias != null) {
                            throw new IOException("Missing certificate alias and multiple matches");
                        }
                        keyAlias = new_key;
                    }
                }
                if (keyAlias == null) {
                    throw new IOException("No matching certificate");
                }
            } else {
                testKey(keyAlias);
            }
            privateKey = (PrivateKey) signerCertKeystore.getKey(keyAlias,
                    password == null ? null : password.toCharArray());
            return this;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }


    public KeyStoreSigner setExtendedCertPath(boolean flag) {
        extendedCertpath = flag;
        return this;
    }
}

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
package org.webpki.crypto;

import java.util.Enumeration;

import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;

/**
 * Sign data using the KeyStore interface.
 */
public class KeyStoreSigner implements X509SignerInterface, CertificateSelectorSpi {

    private PrivateKey privateKey;
    
    private AsymSignatureAlgorithms algorithm;

    private KeyStore signerCertKeystore;

    private String keyAlias;

    private boolean extendedCertpath;

    private boolean ecdsaDerEncoded;


    private KeyStoreSigner testKey(String keyAlias) throws GeneralSecurityException {
        if (!signerCertKeystore.isKeyEntry(keyAlias)) {
            throw new CryptoException("Specified certficate does not have a private key: " + keyAlias);
        }
        return this;
    }


    private X509Certificate[] getCertPath(String keyAlias, boolean pathExpansion) {
        try {
        testKey(keyAlias);
        Certificate[] cp = signerCertKeystore.getCertificateChain(keyAlias);
        X509Certificate[] certificatePath = new X509Certificate[cp.length];
        for (int q = 0; q < cp.length; q++) {
            certificatePath[q] = (X509Certificate) cp[q];
        }
        return certificatePath;
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }


    public CertificateSelection getCertificateSelection(CertificateFilter[] cfs) 
            throws GeneralSecurityException {
        boolean path_expansion = false;
        for (CertificateFilter cf : cfs) {
            if (cf.needsPathExpansion()) {
                path_expansion = true;
                break;
            }
        }
        CertificateSelection cs = new CertificateSelection(this);
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
        return cs;
    }


    public X509Certificate[] getCertificatePath() {
        X509Certificate[] path = getCertPath(keyAlias, true);
        return extendedCertpath ? path : new X509Certificate[]{path[0]};
    }


    public KeyStoreSigner ecdsaAsn1SignatureEncoding(boolean derEncoded) {
        ecdsaDerEncoded = derEncoded;
        return this;
    }


    @Override
    public byte[] signData(byte[] data) {
        try {
            return new SignatureWrapper(algorithm, privateKey)
                           .ecdsaAsn1SignatureEncoding(ecdsaDerEncoded)
                           .update(data)
                           .sign();
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }


    public KeyStoreSigner(KeyStore signerCertKeystore, KeyContainerTypes containerType) {
        this.signerCertKeystore = signerCertKeystore;
    }


    public KeyStoreSigner setKey(String inKeyAlias, String password) 
            throws GeneralSecurityException {
        keyAlias = inKeyAlias;
        if (keyAlias == null) {
            // Search for signer certificate/key:
            Enumeration<String> aliases = signerCertKeystore.aliases();

            while (aliases.hasMoreElements()) {
                String new_key = aliases.nextElement();
                if (signerCertKeystore.isKeyEntry(new_key)) {
                    if (keyAlias != null) {
                        throw new CryptoException("Missing certificate alias and multiple matches");
                    }
                    keyAlias = new_key;
                }
            }
            if (keyAlias == null) {
                throw new CryptoException("No matching certificate");
            }
        } else {
            testKey(keyAlias);
        }
        privateKey = (PrivateKey) signerCertKeystore.getKey(keyAlias,
                password == null ? null : password.toCharArray());
        algorithm = KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm();
        return this;

    }

    public KeyStoreSigner setExtendedCertPath(boolean flag) {
        extendedCertpath = flag;
        return this;
    }

    public void setAlgorithm(AsymSignatureAlgorithms algorithm) {
        this.algorithm = algorithm;
    }
    
    @Override
    public AsymSignatureAlgorithms getAlgorithm() {
        return algorithm;
    }

}

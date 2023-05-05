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
package org.webpki.crypto;

import java.io.IOException;

import java.security.KeyStore;
import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

/**
 * Verify certificates using the KeyStore interface.
 */
public class KeyStoreVerifier implements X509VerifierInterface {

    private X509Store caCertificates;

    private boolean abortOnNonTrusted = true;

    private boolean trusted;

    private X509Certificate[] certificatePath;

    /**
     * Verifier based on a specific keystore.
     *
     * @param caCertsKeyStore Use this keystore for verification
     */
    public KeyStoreVerifier(KeyStore caCertsKeyStore) {
        caCertificates = new X509Store(caCertsKeyStore);
    }

    /**
     * Dummy verifier accepting any certificate.
     */
    public KeyStoreVerifier() {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null);
            caCertificates = new X509Store(ks);
        } catch (GeneralSecurityException | IOException e) {
            throw new CryptoException(e);
        }
        abortOnNonTrusted = false;
    }


    public boolean verifyCertificatePath(X509Certificate[] inCertificatePath) {
        certificatePath = inCertificatePath;
        trusted = caCertificates.verifyCertificates(certificatePath);
        if (abortOnNonTrusted && !trusted) {
            throw new CryptoException("Unknown CA: " + 
                       certificatePath[certificatePath.length - 1].getIssuerX500Principal().getName());
        }
        return trusted;
    }

    public void setTrustedRequired(boolean flag) {
        abortOnNonTrusted = flag;
    }


    public X509Certificate[] getCertificatePath() {
        return certificatePath;
    }


    public X509Certificate getSignerCertificate() {
        return certificatePath[0];
    }
}

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

import java.security.KeyStore;
import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

/**
 * Verify certificates using the KeyStore interface.
 */
public class KeyStoreVerifier implements VerifierInterface {

    private X509Store caCertificates;

    private boolean abortOnNonTrusted = true;

    private boolean trusted;

    private AuthorityInfoAccessCAIssuersSpi aiaCaissuerHandler;

    private X509Certificate[] certificatePath;

    /**
     * Verifier based on a specific keystore.
     *
     * @param caCertsKeyStore Use this keystore for verification
     * @throws IOException for various errors
     */
    public KeyStoreVerifier(KeyStore caCertsKeyStore) throws IOException {
        try {
            caCertificates = new X509Store(caCertsKeyStore);
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
    }

    /**
     * Dummy verifier accepting any certificate.
     *
     * @throws IOException for various errors
     */
    public KeyStoreVerifier() throws IOException {
        try {
            KeyStore ks = KeyStore.getInstance("JKS");
            ks.load(null);
            caCertificates = new X509Store(ks);
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
        abortOnNonTrusted = false;
    }


    public boolean verifyCertificatePath(X509Certificate[] inCertificatePath) throws IOException {
        try {
            certificatePath = inCertificatePath;
            if (aiaCaissuerHandler != null) {
                certificatePath = aiaCaissuerHandler.getUpdatedPath(certificatePath);
            }
            trusted = caCertificates.verifyCertificates(certificatePath);
            if (abortOnNonTrusted && !trusted) {
                throw new IOException("Unknown CA: " + certificatePath[certificatePath.length - 1].getIssuerX500Principal().getName());
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e.getMessage());
        }
        return trusted;
    }

    public void setAuthorityInfoAccessCAIssuersHandler(AuthorityInfoAccessCAIssuersSpi aiaCaissuerHandler) {
        this.aiaCaissuerHandler = aiaCaissuerHandler;
    }


    public void setTrustedRequired(boolean flag) throws IOException {
        abortOnNonTrusted = flag;
    }


    public X509Certificate[] getSignerCertificatePath() throws IOException {
        return certificatePath;
    }


    public X509Certificate getSignerCertificate() throws IOException {
        return certificatePath[0];
    }
}

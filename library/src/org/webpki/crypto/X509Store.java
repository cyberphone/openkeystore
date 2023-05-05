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

import java.util.Enumeration;
import java.util.Hashtable;
import java.util.ArrayList;

import java.security.KeyStore;

import java.security.cert.X509Certificate;
import java.security.cert.Certificate;

import java.security.GeneralSecurityException;

import org.webpki.asn1.cert.*;

/**
 * Class that stores {@link X509Certificate X.509-certificates}.
 * Allows search and verification of certificates using certificate chains.
 */
public class X509Store {

    private Hashtable<DistinguishedName, ArrayList<X509Certificate>> store = new Hashtable<>();

    private void add(X509Certificate certificate) {
        if (certificate == null) {
            return;
        }

        DistinguishedName subject = DistinguishedName.subjectDN(certificate);

        ArrayList<X509Certificate> v = store.get(subject);

        if (v == null) {
            v = new ArrayList<>();
            v.add(certificate);
            store.put(subject, v);
        } else {
            v.add(certificate);
        }
    }

    private boolean add(Certificate[] certificates) {
        if (certificates == null) {
            return false;
        }

        for (int i = 0; i < certificates.length; i++) {
            add((X509Certificate) certificates[i]);
        }
        return true;
    }

    private X509Store() {
    }

    /*
     * Create a X509Store containing all certificates in keyStore.
     */
    public X509Store(KeyStore keyStore) {
        this();
        try {
        for (Enumeration<String> e = keyStore.aliases(); e.hasMoreElements(); ) {
            String alias = e.nextElement();

            // dirty!
            if (!add(keyStore.getCertificateChain(alias))) {
                add((X509Certificate) keyStore.getCertificate(alias));
            }
        }
        } catch (GeneralSecurityException e) {
            throw new CryptoException(e);
        }
    }

    /*
     * Create a X509Store containing all certificates in an array.
     */
    public X509Store(X509Certificate[] certificates) {
        this();
        add(certificates);
    }

    /*
     * Create a X509Store containing all certificates in an array.
     */
    public X509Store(byte[][] certificates) {
        this();
        for (int i = 0; i < certificates.length; i++) {
            add(CertificateUtil.getCertificateFromBlob(certificates[i]));
        }
    }

    /*
     * Returns true if this store contains one or more certificates for <code>subject</code>
     */
    public boolean hasCertificate(DistinguishedName subject) {
        return store.containsKey(subject);
    }

    /*
     * Returns true if this store contains certificate
     */
    public boolean hasCertificate(X509Certificate certificate) {
        DistinguishedName subject = DistinguishedName.subjectDN(certificate);

        for (X509Certificate e : getCertificates(subject)) {
            if (e.equals(certificate)) {
                return true;
            }
        }

        return false;
    }

    /*
     * Returns all certificates matching a given DistinguishedName
     */
    public ArrayList<X509Certificate> getCertificates(DistinguishedName subject) {
        ArrayList<X509Certificate> v = store.get(subject);

        return (v == null) ? new ArrayList<>() : v;
    }

    /*
     * Verify a certificate against the store.
     * 
     * Check if the certificate is either itself in the store or 
     * can be verified by a certificate in the store.
     * 
     */
    public boolean verifyCertificate(X509Certificate certificate) {
        return hasCertificate(certificate) || verifyCertificateByIssuer(certificate);
    }

    private boolean verifyCertificateByIssuer(X509Certificate certificate) {
        return getVerifiedIssuer(certificate) != null;
    }

    /*
     * Returns the (verified) issuer of a certificate if present in this store.
     */
    public X509Certificate getVerifiedIssuer(X509Certificate certificate) {
        DistinguishedName issuer = DistinguishedName.issuerDN(certificate);

        for (X509Certificate e : getCertificates(issuer)) {
            X509Certificate issuerCert = e;

            try {
                certificate.verify(issuerCert.getPublicKey());
                if (!certificate.equals(issuerCert))
                    return issuerCert;
            } catch (GeneralSecurityException gse) {
            }
        }

        return null;
    }

    /*
     * Returns the issuer of a certificate if present in the supplied list of certs.
     * This method will return null if the issuer certificate cannot be found or if the
     * certificate is self-signed.
     */
    public static X509Certificate getVerifiedIssuer(X509Certificate[] certificates,
                                                    X509Certificate certificate) {
        for (int i = 0; i < certificates.length; i++) {
            try {
                certificate.verify(certificates[i].getPublicKey());
                if (!certificate.equals(certificates[i]))
                    return certificates[i];
            } catch (GeneralSecurityException gse) {
            }
        }

        return null;
    }

    /*
     * Verify a certificate against the store.
     * 
     * Checks if the supplied certificate is either itself in
     * the store och can be verified by a certificate in the store,
     * possibly using a certificate chain constructed from other 
     * certificates in the supplied store.
     */
    public boolean verifyCertificate(X509Store chainStore, X509Certificate certificate) {
        return certificate != null &&
                (hasCertificate(certificate) ||
                        verifyCertificate(chainStore, chainStore.getVerifiedIssuer(certificate)) ||
                        verifyCertificateByIssuer(certificate));
    }

    /*
     * Verify a certificate against the store.
     * 
     * Checks if the supplied certificate is either itself in
     * the store och can be verified by a certificate in the store,
     * possibly using a certificate chain constructed from other 
     * certificates in the supplied stores.
     */
    public boolean verifyCertificate(X509Store chainStore1, X509Store chainStore2, X509Certificate certificate) {
        return certificate != null &&
                (hasCertificate(certificate) ||
                        verifyCertificate(chainStore1, chainStore2, chainStore1.getVerifiedIssuer(certificate)) ||
                        verifyCertificate(chainStore1, chainStore2, chainStore2.getVerifiedIssuer(certificate)) ||
                        verifyCertificateByIssuer(certificate));
    }

    /*
     * Verify a certificate against the store.
     * 
     * Checks if the i:th certificate in the array is either itself in
     * the store och can be verified by a certificate in the store,
     * possibly using a certificate chain constructed from other 
     * certificates in the array.
     */
    public boolean verifyCertificate(X509Certificate[] certificates, int i) {
        return verifyCertificate(certificates, certificates[i]);
    }

    /*
     * Verify a certificate against the store.
     * 
     * Checks if the certificate is either itself in
     * the store och can be verified by a certificate in the store,
     * possibly using a certificate chain constructed from
     * certificates in the array.
     */
    public boolean verifyCertificate(X509Certificate[] certificates, X509Certificate certificate) {
        return verifyCertificate(new X509Store(certificates), certificate);
    }

    /*
     * Verify an array of certificates against the store.
     * 
     * Checks if the certificates are either themselves in
     * the store och can be verified by certificates in the store,
     * possibly using certificate chains constructed from
     * certificates in the array.
     */
    public boolean verifyCertificates(X509Certificate[] certificates) {
        X509Store approved = new X509Store();

        boolean[] done = new boolean[certificates.length];

        // n = number of certificates verified so far.
        int n = 0;

        // Every loop may verify zero or more certificates.
        // If no certificates are verified in an iteration
        // we have failed.
        for (int i = 0; i < certificates.length; i++) {
            int oldN = n;

            for (int j = 0; j < certificates.length; j++) {
                if (!done[j] &&
                        (approved.hasCertificate(certificates[j]) ||
                                this.hasCertificate(certificates[j]) ||
                                approved.verifyCertificateByIssuer(certificates[j]) ||
                                this.verifyCertificateByIssuer(certificates[j]))) {
                    approved.add(certificates[j]);
                    done[j] = true;
                    n++;
                }
            }

            // No cert has been verified in this loop.
            if (n == oldN) {
                return false;
            }

            // If all certificates have been verified we are finished.
            if (n == certificates.length) {
                return true;
            }
        }

        throw new InternalError("KEX!");  // This statement shall never be reached.
    }
}

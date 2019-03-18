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
import java.io.Serializable;

import java.util.Hashtable;

import java.security.GeneralSecurityException;

import java.security.cert.X509Certificate;

import org.webpki.util.URLDereferencer;

public class AuthorityInfoAccessCAIssuersCache implements AuthorityInfoAccessCAIssuersSpi, Serializable {

    private static final long serialVersionUID = 1L;

    private Hashtable<String, X509Certificate[]> cache = new Hashtable<String, X509Certificate[]>();

    public X509Certificate[] getUpdatedPath(X509Certificate[] inputPath) throws IOException {
        String[] aia_caissuers = CertificateUtil.getAIACAIssuers(inputPath[inputPath.length - 1]);
        if (aia_caissuers != null) {
            for (String uri : aia_caissuers) {
                X509Certificate[] ca_path = cache.get(uri);
                if (ca_path == null) {
                    try {
                        synchronized (this) {
                            X509Certificate[] temp_path = null;
                            URLDereferencer dref = new URLDereferencer(uri);
                            if (dref.getMimeType().equals("application/x-x509-ca-cert") ||
                                    dref.getMimeType().equals("application/pkix-cert")) {
                                temp_path = new X509Certificate[]{CertificateUtil.getCertificateFromBlob(dref.getData())};
                            } else if (dref.getMimeType().equals("application/x-pkcs7-certificates") ||
                                    dref.getMimeType().equals("application/pkcs7-mime")) {
                                temp_path = CertificateUtil.getSortedPathFromPKCS7Bag(dref.getData());
                            } else {
                                throw new IOException("Unknown CA data object");
                            }
                            temp_path = getUpdatedPath(temp_path);
                            inputPath[inputPath.length - 1].verify(temp_path[0].getPublicKey());
                            cache.put(uri, ca_path = temp_path);
                        }
                    } catch (IOException ioe) {
                        System.out.println("Silently failed on AIA url: " + uri + " " + ioe.getMessage());
                    } catch (GeneralSecurityException gse) {
                        System.out.println("Format error in AIA url: " + uri + " " + gse.getMessage());
                    }
                }
                if (ca_path != null) {
                    X509Certificate[] cert_path = new X509Certificate[ca_path.length + inputPath.length];
                    int q = 0;
                    for (X509Certificate tcert : inputPath) {
                        cert_path[q++] = tcert;
                    }
                    for (X509Certificate tcert : ca_path) {
                        cert_path[q++] = tcert;
                    }
                    return cert_path;
                }
            }
        }
        return inputPath;
    }


    public void preInitialize(X509Certificate[] caCertificatePath, String uri) {
        cache.put(uri, caCertificatePath);
    }


    public void preInitialize(X509Certificate caCertificate, String uri) {
        preInitialize(new X509Certificate[]{caCertificate}, uri);
    }

}

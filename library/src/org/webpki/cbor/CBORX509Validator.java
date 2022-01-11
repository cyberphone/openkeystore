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
package org.webpki.cbor;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.X509VerifierInterface;

import org.webpki.crypto.signatures.SignatureWrapper;

/**
 * Class for CBOR X509 signature validation.
 * 
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORX509Validator extends CBORValidator {
    
    X509VerifierInterface verifier;
    
    /**
     * Initialize validator with a verifier.
     * 
     * @param verifier The verifier interface
     */
    public CBORX509Validator(X509VerifierInterface verifier) {
        this.verifier = verifier;
    }

    @Override
    void validate(CBORMap signatureObject, 
                  int coseAlgorithmId,
                  byte[] optionalKeyId,
                  byte[] signatureValue,
                  byte[] signedData) throws IOException, GeneralSecurityException {
        
        // Get signature algorithm.
        AsymSignatureAlgorithms signatureAlgorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Acquire certificate(path).
        X509Certificate[] certificatePath = signatureObject.getObject(
                CBORSigner.CERT_PATH_LABEL).getArray().getCertificatePath();
        
        // Read the public key of the signature certificate.
        PublicKey publicKey = certificatePath[0].getPublicKey();
        
        // Verify that the public key matches the signature algorithm.
        KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
        if (signatureAlgorithm.getKeyType() != keyAlgorithm.getKeyType()) {
            throw new GeneralSecurityException("Algorithm " + signatureAlgorithm + 
                                  " does not match key type " + keyAlgorithm);
        }
        
        // Finally, verify the signature.
        if (!new SignatureWrapper(signatureAlgorithm, publicKey)
                 .update(signedData)
                 .verify(signatureValue)) {
            throw new GeneralSecurityException("Bad signature for key: " + publicKey.toString());
        }

        // Lookup and validate certificatePath.
        if (!verifier.verifyCertificatePath(certificatePath)) {
            throw new GeneralSecurityException("Untrusted cert path");
        }
    }
}

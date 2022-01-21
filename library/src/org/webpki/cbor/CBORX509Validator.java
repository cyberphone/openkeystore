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

import java.security.cert.X509Certificate;

import java.util.ArrayList;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;

/**
 * Class for CBOR X509 signature validation.
 * 
 * It uses COSE algorithms but relies on CSF for the packaging.
 * 
 * Note that validator objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe. 
 */
public class CBORX509Validator extends CBORValidator {
    
    /**
     * For checking signature parameters
     */
    public interface SignatureParameters {

        /**
         * Check signature data.
         * 
         * A relying party is supposed to verify that the
         * certificate(path) is trusted and that the
         * signature algorithm meets their policy requirements.
         * 
         * @param certificatePath Path to be verified
         * @param signatureAlgorithm The specified signature algorithm
         * @throws IOException
         * @throws GeneralSecurityException
         */
        void check(X509Certificate[] certificatePath, AsymSignatureAlgorithms signatureAlgorithm)
            throws IOException, GeneralSecurityException;
    }
    
    SignatureParameters checker;

    /**
     * Initialize validator with a parameter checker.
     * 
     * @param checker The checker interface
     */
    public CBORX509Validator(SignatureParameters checker) {
        this.checker = checker;
    }
    
    /**
     * Get certificate path from a CBOR array.
 
     * Note that the array must only contain a
     * list of X509 certificates in DER format.
     * The certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.
     * 
     * See {@link CBORX509Signer#encodeCertificateArray(X509Certificate[])}.
     * 
     * @return Certificate path
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static X509Certificate[] decodeCertificateArray(CBORArray array) 
            throws IOException, GeneralSecurityException {
        ArrayList<byte[]> blobs = new ArrayList<>();
        int index = 0;
        do {
            blobs.add(array.objectList.get(index).getByteString());
        } while (++index < array.objectList.size());
        return CertificateUtil.makeCertificatePath(blobs);
    }
 
    @Override
    void validate(CBORMap signatureObject, 
                  int coseAlgorithmId,
                  CBORObject optionalKeyId,
                  byte[] signatureValue,
                  byte[] signedData) throws IOException, GeneralSecurityException {

        // keyId and certificates? Never!
        CBORSigner.checkKeyId(optionalKeyId);
        
        // Get signature algorithm.
        AsymSignatureAlgorithms signatureAlgorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Fetch certificate(path).
        X509Certificate[] certificatePath = decodeCertificateArray(
                signatureObject.getObject(CBORSigner.CERT_PATH_LABEL).getArray());
        
        // Now we have everything needed for validating the signature.
        CBORAsymKeyValidator.asymKeySignatureValidation(certificatePath[0].getPublicKey(),
                                                        signatureAlgorithm, 
                                                        signedData, 
                                                        signatureValue);

        // Finally, check certificate(path) and signature algorithm.
        checker.check(certificatePath, signatureAlgorithm);
    }
}

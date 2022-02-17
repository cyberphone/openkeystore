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

import org.webpki.crypto.AsymSignatureAlgorithms;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for CBOR X509 signature validation.
 *<p>
 * See {@link CBORValidator} for details.
 *</p> 
 * <p>
 * Note that X509 signatures do not permit the use of a keyId.
 * </p>
 */
public class CBORX509Validator extends CBORValidator {
    
    /**
     * For checking signature parameters.
     */
    public interface SignatureParameters {

        /**
         * Checks signature data.
         * <p>
         * A relying party is supposed to verify that the
         * certificate(path) is trusted and that the supplied
         * algorithm meets their policy requirements.
         * Deviations should force the implementation to throw an exception.
         * </p>
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
     * Initializes X509 validator with a parameter checker.
     * 
     * @param checker The checker interface
     */
    public CBORX509Validator(SignatureParameters checker) {
        this.checker = checker;
    }
 
    @Override
    void coreValidation(CBORMap signatureObject, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) throws IOException, GeneralSecurityException {

        // keyId and certificates? Never!
        CBORCryptoUtils.checkKeyId(optionalKeyId);
        
        // Get signature algorithm.
        AsymSignatureAlgorithms signatureAlgorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Fetch certificate(path).
        X509Certificate[] certificatePath = CBORCryptoUtils.decodeCertificateArray(
                signatureObject.getObject(CERT_PATH_LABEL).getArray());
        
        // Now we have everything needed for validating the signature.
        CBORAsymKeyValidator.asymKeySignatureValidation(certificatePath[0].getPublicKey(),
                                                        signatureAlgorithm, 
                                                        signedData, 
                                                        signatureValue);

        // Finally, check certificate(path) and signature algorithm.
        checker.check(certificatePath, signatureAlgorithm);
    }
}

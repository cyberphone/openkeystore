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
package org.webpki.cbor;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for validating X.509 signatures.
 *<p>
 * Also see {@link CBORValidator}.
 *</p> 
 * <p>
 * Note that X.509 signatures do not permit the use of a keyId.
 * </p>
 */
public class CBORX509Validator extends CBORValidator<CBORX509Validator> {
    
    /**
     * Interface for verifying signature meta data.
     */
    public interface Parameters {

        /**
         * Verify signature meta data.
         * <p>
         * A relying party is supposed to verify that the
         * certificate(path) is trusted and that the supplied
         * algorithm meets their policy requirements.
         * Deviations should force the implementation to throw an exception.
         * </p>
         * 
         * @param certificatePath Path to be verified
         * @param algorithm Signature algorithm
         */
        void verify(X509Certificate[] certificatePath, AsymSignatureAlgorithms algorithm);
    }
    
    Parameters parameters;

    /**
     * Creates X.509 validator object with a parameter verifier.
     * 
     * @param parameters Parameters implementation
     */
    public CBORX509Validator(Parameters parameters) {
        super(true);
        this.parameters = parameters;
    }
 
    @Override
    void coreValidation(CBORMap csfContainer, 
                        int coseAlgorithmId,
                        CBORObject optionalKeyId,
                        byte[] signatureValue,
                        byte[] signedData) {

        // keyId and certificates? Never!
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
        
        // Get signature algorithm.
        AsymSignatureAlgorithms algorithm =
                AsymSignatureAlgorithms.getAlgorithmFromId(coseAlgorithmId);
        
        // Fetch certificate(path).
        X509Certificate[] certificatePath = CBORCryptoUtils.decodeCertificateArray(
                csfContainer.get(CXF_CERT_PATH_LBL).getArray());
        
        // Now we have everything needed for validating the signature.
        SignatureWrapper.validate(certificatePath[0].getPublicKey(),
                                  algorithm, 
                                  signedData, 
                                  signatureValue,
                                  null);

        // Finally, check certificate(path) and signature algorithm.
        parameters.verify(certificatePath, algorithm);
    }

    @Override
    CBORX509Validator getThis() {
        return this;
    }
}

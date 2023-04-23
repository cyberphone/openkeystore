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

import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR X509 signatures.
 * <p>
 * See {@link CBORSigner} for details.
 * </p>
 * <p> 
 * Note that X509 signatures do not permit the use of a <code>keyId</code>.
 * </p>
 */
public class CBORX509Signer extends CBORSigner {

    X509SignerInterface signer;
    
    /**
     * Initializes a signer with an external interface.
     * 
     * @param signer Custom signer
     */
    public CBORX509Signer(X509SignerInterface signer) {
        this.signer = signer;
    }
    
    /**
     * Initializes an X509 signer with a private key.
     * <p>
     * The signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * </p>
     * @param privateKey Signature key
     * @param certificatePath A matching non-null certificate path
     */
    public CBORX509Signer(PrivateKey privateKey, X509Certificate[] certificatePath) {
        this(privateKey, 
             certificatePath, 
             KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

    /**
     * Initializes an X509 signer with a private key.
     * 
     * @param privateKey Signature key
     * @param certificatePath A matching non-null certificate path
     * @param algorithm Signature algorithm
     */
    public CBORX509Signer(PrivateKey privateKey,
                          X509Certificate[] certificatePath,
                          AsymSignatureAlgorithms algorithm) {
        signer = new X509SignerInterface() {

            @Override
            public byte[] signData(byte[] data) {
                return SignatureWrapper.sign(privateKey, algorithm, data, provider);
            }

            @Override
            public X509Certificate[] getCertificatePath() {
                return certificatePath;
            }

            @Override
            public AsymSignatureAlgorithms getAlgorithm() {
                return algorithm;
            }
            
        };
    }

    @Override
    byte[] coreSigner(byte[] dataToBeSigned) {
        return signer.signData(dataToBeSigned);
    }
    
    @Override
    void additionalItems(CBORMap signatureObject) {
        // X509 signatures mandate a certificate path.
        signatureObject.setObject(CERT_PATH_LABEL, 
                                  CBORCryptoUtils.encodeCertificateArray(signer.getCertificatePath()));
        // Key IDs are always rejected.
        CBORCryptoUtils.rejectPossibleKeyId(optionalKeyId);
    }

    @Override
    SignatureAlgorithms getAlgorithm() {
        return signer.getAlgorithm();
    }
}

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
import java.security.PrivateKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.X509SignerInterface;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.crypto.signatures.SignatureWrapper;

import static org.webpki.cbor.CBORCryptoConstants.*;

/**
 * Class for creating CBOR X509 signatures.
 * 
 * It uses COSE algorithms but relies on CSF for the packaging.
 * 
 * Note that signer objects may be used any number of times
 * (assuming that the same parameters are valid).  They are also
 * thread-safe.
 * 
 * X509 signatures do not permit the use of a keyId.
 */
public class CBORX509Signer extends CBORSigner {

    AsymSignatureAlgorithms algorithm;
    
    X509SignerInterface signer;
    
    X509Certificate[] certificatePath;

    /**
     * Initialize signer.
     * 
     * @param signer Custom signer
     * @throws GeneralSecurityException 
     * @throws IOException 
     */
    public CBORX509Signer(X509SignerInterface signer) throws IOException,
                                                             GeneralSecurityException {
        this.signer = signer;
        setAlgorithm(signer.getAlgorithm());
        this.certificatePath = signer.getCertificatePath();
    }
    
    /**
     * Initialize signer.
     * 
     * The default signature algorithm to use is based on the recommendations
     * in RFC 7518.
     * 
     * @param privateKey The key to sign with
     * @param certificatePath A matching non-null certificate path
     * @throws IOException 
     * @throws GeneralSecurityException 
     */
    public CBORX509Signer(PrivateKey privateKey, X509Certificate[] certificatePath) 
            throws IOException, GeneralSecurityException {
        this.certificatePath = certificatePath;
        signer = new X509SignerInterface() {

            @Override
            public byte[] signData(byte[] dataToBeSigned) throws IOException,
                                                                 GeneralSecurityException {
                return new SignatureWrapper(algorithm, privateKey, provider)
                        .update(dataToBeSigned)
                        .sign();            
            }

            @Override
            public X509Certificate[] getCertificatePath()
                    throws IOException, GeneralSecurityException {
                // TODO Auto-generated method stub
                return null;
            }
            
        };
        setAlgorithm(KeyAlgorithms.getKeyAlgorithm(privateKey).getRecommendedSignatureAlgorithm());
    }

     /**
     * Set signature algorithm.
     * 
     * @param algorithm The algorithm
     * @return this
     * @throws GeneralSecurityException 
     * @throws IOException 
     */
    public CBORX509Signer setAlgorithm(AsymSignatureAlgorithms algorithm) throws IOException {
        this.algorithm = algorithm;
        this.coseAlgorithmId = algorithm.getCoseAlgorithmId();
        return this;
    }    

    @Override
    byte[] signData(byte[] dataToBeSigned) throws IOException, GeneralSecurityException {
        return signer.signData(dataToBeSigned);
    }
    
    /**
     * Encode certificate path into a CBOR array.
 
     * Note that the certificates must be in ascending
     * order with respect to parenthood.  That is,
     * the first certificate would typically be
     * an end-entity certificate.
     * 
     * See  {@link CBORX509Validator#decodeCertificateArray(CBORArray)}.
     * 
     * @param certificatePath The certificate path to be converted to CBOR 
     * 
     * @return CBORArray
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static CBORArray encodeCertificateArray(X509Certificate[] certificatePath) 
            throws IOException, GeneralSecurityException {
        CBORArray array = new CBORArray();
        for (X509Certificate certificate : CertificateUtil.checkCertificatePath(certificatePath)) {
            array.addObject(new CBORByteString(certificate.getEncoded()));
        }
        return array;
    }

    @Override
    void additionalItems(CBORMap signatureObject) 
            throws IOException, GeneralSecurityException {
        signatureObject.setObject(CERT_PATH_LABEL, encodeCertificateArray(certificatePath));
        checkKeyId(optionalKeyId);
    }
}

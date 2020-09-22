/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.jose;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;

import org.webpki.util.Base64;
import org.webpki.util.Base64URL;

/**
 * Core JWS support class
 */
public class JOSESupport {
    
    JOSESupport() {}
    
    public static final String ALG_JSON = "alg";
    public static final String KID_JSON = "kid";
    public static final String JWK_JSON = "jwk";
    public static final String X5C_JSON = "x5c";
    
    public static final String EdDSA    = "EdDSA";

    /**
     * Super class of validators
     */
    public static abstract class CoreSignatureValidator {
        
        CoreSignatureValidator() {};
 
        abstract void validate(byte[] signedData,
                               JwsDecoder jwsDecoder) throws IOException, GeneralSecurityException;

    }

    /**
     * Super class of signature key holders
     * @author Anders
     *
     */
    public abstract static class CoreKeyHolder {
        
        PublicKey optionalPublicKey;
        
        X509Certificate[] optionalCertificatePath;
        
        String optionalKeyId;
        
        SignatureAlgorithms signatureAlgorithm;
        
        private CoreKeyHolder(SignatureAlgorithms signatureAlgorithm) {
            this.signatureAlgorithm = signatureAlgorithm;
        }

        byte[] secretKey;

        CoreKeyHolder(byte[] secretKey, SignatureAlgorithms signatureAlgorithm) {
            this(signatureAlgorithm);
            this.secretKey = secretKey;
        }

        PrivateKey privateKey;

        CoreKeyHolder(PrivateKey privateKey, SignatureAlgorithms signatureAlgorithm) {
            this(signatureAlgorithm);
            this.privateKey = privateKey;
        }

        /**
         * Adds "kid" to the JWS header
         * @param keyId Actual value
         * @return
         */
        public CoreKeyHolder setKeyId(String keyId) {
            this.optionalKeyId = keyId;
            return this;
        }
    }
    
    /**
     * Validate compact JWS signature
     * @param jwsDecoder Decoded header and string
     * @param optionalJwsPayload Must be supplied for detached mode, null otherwise
     * @param signatureValidator Key + algorithm
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static void validateJwsSignature(JwsDecoder jwsDecoder,
                                            byte[] optionalJwsPayload,
                                            CoreSignatureValidator signatureValidator) 
    throws IOException, GeneralSecurityException {

        // Dealing with detached and in-line
        String jwsPayloadB64U;
        if (jwsDecoder.optionalJwsPayloadB64U == null) {
            if (optionalJwsPayload == null) {
                throw new IllegalArgumentException("Detached payload missing");
            }
            jwsPayloadB64U = Base64URL.encode(optionalJwsPayload);
        } else {
            if (optionalJwsPayload != null) {
                throw new IllegalArgumentException(
                        "Both external and JWS-supplied payload? Set argument to \"null\".");
            }
            jwsPayloadB64U = jwsDecoder.optionalJwsPayloadB64U;
        }
        
        // Delegate validation
        signatureValidator.validate((jwsDecoder.jwsProtectedHeaderB64U + 
                                     "." + 
                                     jwsPayloadB64U).getBytes("utf-8"),
                                    jwsDecoder);
    }

    /**
     * Create compact JWS signature
     * @param jwsEncoder Header element data and signature key
     * @param jwsPayload Binary payload
     * @param detached True if payload is not to be supplied in the string
     * @return JWS compact (string)
     * @throws IOException
     * @throws GeneralSecurityException
     */
    public static String createJwsSignature(JwsEncoder jwsEncoder,
                                            byte[] jwsPayload,
                                            boolean detached)
    throws IOException, GeneralSecurityException {

        // Encode possible JWK
        if (jwsEncoder.coreKeyHolder.optionalPublicKey != null) {
            jwsEncoder.jwsProtectedHeader.setObject(JWK_JSON, 
                                                    JSONObjectWriter.createCorePublicKey(
                                                        jwsEncoder.coreKeyHolder.optionalPublicKey,
                                                        AlgorithmPreferences.JOSE));
        }

        // Encode possible X5C
        if (jwsEncoder.coreKeyHolder.optionalCertificatePath != null) {
            JSONArrayWriter certPath = jwsEncoder.jwsProtectedHeader.setArray(X5C_JSON);
            for (X509Certificate cert : jwsEncoder.coreKeyHolder.optionalCertificatePath) {
                certPath.setString(new Base64(false).getBase64StringFromBinary(cert.getEncoded()));
            }
        }

        // Encode possible KID
        if (jwsEncoder.coreKeyHolder.optionalKeyId != null) {
            jwsEncoder.jwsProtectedHeader.setString(KID_JSON, 
                                                    jwsEncoder.coreKeyHolder.optionalKeyId);
        }
        
        // Create data to be signed
        String jwsProtectedHeaderB64U = Base64URL.encode(
                jwsEncoder.jwsProtectedHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
        String jwsPayloadB64U = Base64URL.encode(jwsPayload);
        byte[] dataToBeSigned = (jwsProtectedHeaderB64U + "." + jwsPayloadB64U).getBytes("utf-8");
        
        // Sign data
        byte[] signature;
        if (jwsEncoder.coreKeyHolder.signatureAlgorithm.isSymmetric()) {
            signature = ((MACAlgorithms)jwsEncoder.coreKeyHolder.signatureAlgorithm)
                            .digest(jwsEncoder.coreKeyHolder.secretKey, dataToBeSigned);
        } else {
            signature = new SignatureWrapper(
                    (AsymSignatureAlgorithms)jwsEncoder.coreKeyHolder.signatureAlgorithm,
                    jwsEncoder.coreKeyHolder.privateKey)
                        .update(dataToBeSigned)
                        .sign();
        }
        
        // Return JWS string
        return jwsProtectedHeaderB64U +
                "." +
                (detached ? "" : jwsPayloadB64U) +
                "." +
                Base64URL.encode(signature);
    }
}

/*
 *  Copyright 2006-2019 WebPKI.org (http://webpki.org).
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
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64;
import org.webpki.util.Base64URL;

public class JOSESupport {
    
    public static final String ALG_JSON = "alg";
    public static final String KID_JSON = "kid";
    public static final String JWK_JSON = "jwk";
    public static final String X5C_JSON = "x5c";
    
    public static final String EdDSA    = "EdDSA";
    
    public static abstract class CoreSignatureValidator {
        
        CoreSignatureValidator() {};
 
        abstract void validate(byte[] signedData,
                      JwsDecoder jwsDecoder) throws IOException, GeneralSecurityException;

    }

    public abstract static class CoreKeyHolder {

        byte[] secretKey;

        protected CoreKeyHolder(byte[] secretKey) {
            this.secretKey = secretKey;
        }

        PrivateKey privateKey;

        protected CoreKeyHolder(PrivateKey privateKey) {
            this.privateKey = privateKey;
        }

        abstract boolean isSymmetric();

        byte[] getSecretKey() {
            return secretKey;
        }

        PrivateKey getPrivateKey() {
            return privateKey;
        }
    }
    
    public static X509Certificate[] getCertificatePath(JSONObjectReader joseObject) throws IOException {
        JSONArrayWriter path = new JSONArrayWriter();
        for (String certB64 : joseObject.getStringArray(X5C_JSON)) {
            path.setString(certB64.replace("=","")
                                  .replace('/', '_')
                                  .replace('+', '-'));
        }
        return JSONParser.parse(path.serializeToString(JSONOutputFormats.NORMALIZED))
            .getJSONArrayReader().getCertificatePath();
    }

    public static void setCertificatePath(JSONObjectWriter joseObject,
                                          X509Certificate[] certificatePath)
    throws IOException, GeneralSecurityException {
        JSONArrayWriter certPath = joseObject.setArray(X5C_JSON);
        for (X509Certificate cert : certificatePath) {
            certPath.setString(new Base64(false).getBase64StringFromBinary(cert.getEncoded()));
        }
    }

    public static void setPublicKey(JSONObjectWriter joseObject,
                                    PublicKey publicKey) throws IOException {
        joseObject.setObject(JWK_JSON, 
                             JSONObjectWriter.createCorePublicKey(publicKey,
                                                                  AlgorithmPreferences.JOSE));
    }

    public static PublicKey getPublicKey(JSONObjectReader joseObject) throws IOException {
        return joseObject.getObject(JWK_JSON).getCorePublicKey(AlgorithmPreferences.JOSE);
    }
    
    public static String getKeyId(JSONObjectReader joseObject) throws IOException {
        return joseObject.getString(KID_JSON);
    }

    public static void setKeyId(JSONObjectWriter joseObject, String keyId) throws IOException {
        joseObject.setString(KID_JSON, keyId);
    }

    public static JSONObjectWriter setSignatureAlgorithm(JSONObjectWriter joseObject, 
                                                         SignatureAlgorithms signatureAlgorithm) 
    throws IOException {
        return joseObject.setString(ALG_JSON, 
                                    signatureAlgorithm.isOkp() ? 
             EdDSA : signatureAlgorithm.getAlgorithmId(AlgorithmPreferences.JOSE));
    }

    public static void validateJwsSignature(JwsDecoder jwsDecoder,
                                            byte[] optionalJwsPayload,
                                            CoreSignatureValidator signatureValidator) 
    throws IOException, GeneralSecurityException {
        String jwsPayloadB64U;
        if (jwsDecoder.optionalJwsPayloadB64U == null) {
            if (optionalJwsPayload == null) {
                throw new IOException("Detached payload missing");
            }
            jwsPayloadB64U = Base64URL.encode(optionalJwsPayload);
        } else {
            if (optionalJwsPayload != null) {
                throw new IOException("Multiple payloads");
            }
            jwsPayloadB64U = jwsDecoder.optionalJwsPayloadB64U;
        }
        signatureValidator.validate((jwsDecoder.jwsProtectedHeaderB64U + 
                                     "." + 
                                     jwsPayloadB64U).getBytes("utf-8"),
                                    jwsDecoder);
    }

    public static String createJwsSignature(JSONObjectWriter jwsProtectedHeader,
                                            byte[] jwsPayload,
                                            CoreKeyHolder coreKeyHolder,
                                            SignatureAlgorithms signatureAlgorithm,
                                            boolean detached)
    throws IOException, GeneralSecurityException {
        if (jwsProtectedHeader == null) {
            jwsProtectedHeader = new JSONObjectWriter();
        }
        if (!new JSONObjectReader(jwsProtectedHeader).hasProperty(ALG_JSON)) {
            setSignatureAlgorithm(jwsProtectedHeader, signatureAlgorithm);
        }
        String jwsHeaderB64U = 
                Base64URL.encode(jwsProtectedHeader.serializeToBytes(JSONOutputFormats.NORMALIZED));
        String jwsPayloadB64U = Base64URL.encode(jwsPayload);
        byte[] dataToBeSigned = (jwsHeaderB64U + "." + jwsPayloadB64U).getBytes("utf-8");
        byte[] signature;
        if (coreKeyHolder.isSymmetric()) {
            signature = ((MACAlgorithms)signatureAlgorithm).digest(coreKeyHolder.getSecretKey(), 
                                                                   dataToBeSigned);
        } else {
            signature = new SignatureWrapper((AsymSignatureAlgorithms)signatureAlgorithm,
                                             coreKeyHolder.getPrivateKey()).update(dataToBeSigned).sign();
        }
        return jwsHeaderB64U + 
                "." +
                (detached ? "" : jwsPayloadB64U) + 
                "." + 
                Base64URL.encode(signature);
    }
}

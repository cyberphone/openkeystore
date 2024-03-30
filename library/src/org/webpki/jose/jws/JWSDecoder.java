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
package org.webpki.jose.jws;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CryptoException;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import static org.webpki.jose.JOSEKeyWords.*;

import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;
import org.webpki.util.UTF8;

/**
 * JWS and JWS/CT decoder
 */
public class JWSDecoder {
    
    String jwsHeaderB64U;
    
    JSONObjectReader jwsHeader;
    
    String jwsPayloadB64U;
    
    JSONObjectReader savedJWSCtObject;
    
    boolean validated;
    
    SignatureAlgorithms signatureAlgorithm;
    
    byte[] signature;
    
    PublicKey optionalPublicKey;
    
    X509Certificate[] optionalCertificatePath;
    
    String optionalKeyId;
    
    private void checkValidation() {
        if (!validated) {
            throw new CryptoException("Trying to access payload before validation");
        }        
    }
    
    private void decodeJWSString(String jwsString) {

        // Extract the JWS elements
        int endOfHeader = jwsString.indexOf('.');
        int startOfSignature = jwsString.lastIndexOf('.');
        if (endOfHeader == startOfSignature - 1)
        if (endOfHeader < 10 ||  startOfSignature > jwsString.length() - 10) {
            throw new CryptoException("JWS syntax error");
        }
        if (endOfHeader < startOfSignature - 1) {
            // In-line signature
            jwsPayloadB64U = jwsString.substring(endOfHeader + 1, startOfSignature);
            Base64URL.decode(jwsPayloadB64U);  // Syntax check
        }
        
        // Begin decoding the JWS header
        jwsHeaderB64U = jwsString.substring(0, endOfHeader);
        jwsHeader = JSONParser.parse(Base64URL.decode(jwsHeaderB64U));
        String algorithmProperty = jwsHeader.getString(ALG_JSON);
        
        // Get the binary signature
        signature = Base64URL.decode(jwsString.substring(startOfSignature + 1));

        // This is pretty ugly, two different conventions in the same standard!
        if (algorithmProperty.equals(EdDSA)) {
            signatureAlgorithm = signature.length == 64 ? 
                        AsymSignatureAlgorithms.ED25519 : AsymSignatureAlgorithms.ED448;
        } else if (algorithmProperty.startsWith("HS")) {
            signatureAlgorithm = 
                    HmacAlgorithms.getAlgorithmFromId(algorithmProperty,
                                                     AlgorithmPreferences.JOSE);
        } else {
            signatureAlgorithm =
                    AsymSignatureAlgorithms.getAlgorithmFromId(algorithmProperty, 
                                                               AlgorithmPreferences.JOSE);
        }
        
        // We don't bother about any other header data than possible public key
        // elements modulo JKU and X5U
        
        // Decode possible JWK
        if (jwsHeader.hasProperty(JWK_JSON)) {
            optionalPublicKey = 
                    jwsHeader.getObject(JWK_JSON)
                        .getCorePublicKey(AlgorithmPreferences.JOSE);
        }

        // Decode possible X5C?
        if (jwsHeader.hasProperty(X5C_JSON)) {
            if (optionalPublicKey != null) {
                throw new CryptoException("Both X5C and JWK?");
            }
            JSONArrayWriter path = new JSONArrayWriter();
            for (String certB64 : jwsHeader.getStringArray(X5C_JSON)) {
                path.setString(certB64.replace("=","")
                                      .replace('/', '_')
                                      .replace('+', '-'));
            }
            optionalCertificatePath = 
                    JSONParser.parse(path.serializeToString(JSONOutputFormats.NORMALIZED))
                        .getJSONArrayReader().getCertificatePath();
            optionalPublicKey = optionalCertificatePath[0].getPublicKey();
        }
        if (signatureAlgorithm.isSymmetric() && optionalPublicKey != null) {
            throw new CryptoException("Mix of symmetric and asymmetric elements?");
        }
        
        // Decode possible KID
        optionalKeyId = jwsHeader.getStringConditional(KID_JSON);
    }
    
    /**
     * JWS compact mode signature decoder.
     * @param jwsString The actual JWS string.  If there is no payload detached mode is assumed
     */
    public JWSDecoder(String jwsString) {
        decodeJWSString(jwsString);
    }

    /**
     * JWS/CT signature decoder.
     * Note that the <code>jwsCtObject</code> remains <i>unmodified</i>.
     * @param jwsCtObject The signed JSON object
     * @param signatureProperty Name of top-level property holding the JWS string
     */
    public JWSDecoder(JSONObjectReader jwsCtObject, String signatureProperty) {

        // Do not alter the original!
        savedJWSCtObject = jwsCtObject.clone();
        String jwsString = savedJWSCtObject.getString(signatureProperty);
        if (!jwsString.contains("..")) {
            throw new CryptoException("JWS detached mode syntax error");
        }
        savedJWSCtObject.removeProperty(signatureProperty);
        jwsPayloadB64U = Base64URL.encode(
                savedJWSCtObject.serializeToBytes(JSONOutputFormats.CANONICALIZED));
        decodeJWSString(jwsString);
    }

    /**
     * Get JWS header.
     * @return JWS header as a JSON object.
     */
    public JSONObjectReader getJWSHeaderAsJson() {
        return jwsHeader;
    }

    /**
     * Get JWS header.
     * @return JWS header as a verbatim string copy after Base64Url-decoding.
      */
    public String getJWSHeaderAsString() {
        return UTF8.decode(Base64URL.decode(jwsHeaderB64U));
    }
    
    /**
     * Get signature algorithm.
     */
    public SignatureAlgorithms getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    /**
     * Get optional "jwk".
     * @return Public key or <b>null</b> if there is no "jwk" property in the JWS header.
     */
    public PublicKey getOptionalPublicKey() {
        return optionalPublicKey;
    }

    /**
     * Get optional "x5c".
     * @return Certificate path or <b>null</b> if there is no "x5c" property in the JWS header.
     */
    public X509Certificate[] getOptionalCertificatePath() {
        return optionalCertificatePath;
    }

    /**
     * Get optional "kid".
     * @return Key identifier or <b>null</b> if there is no "kid" property in the JWS header.
     */
    public String getOptionalKeyId() {
        return optionalKeyId;
    }

    /**
     * Get JWS payload.
     * Note that this method throws an exception if the
     * {@link org.webpki.jose.jws.JWSDecoder}
     * object signature have not yet been
     * {@link org.webpki.jose.jws.JWSValidator#validate(JWSDecoder) validated}.
     * For JWS/CT, the payload holds the canonicalized
     * version of the 
     * {@link org.webpki.jose.jws.JWSDecoder#JWSDecoder(JSONObjectReader, String) jwsCtObject}
     * with the
    * {@link org.webpki.jose.jws.JWSDecoder#JWSDecoder(JSONObjectReader, String) signatureProperty}
     * removed.
     * @return Payload binary
     */
    public byte[] getPayload() {
        checkValidation();
        return Base64URL.decode(jwsPayloadB64U);
    }

    /**
     * Get JWS payload.
     * Note that this method throws an exception if the
     * {@link org.webpki.jose.jws.JWSDecoder}
     * object signature have not yet been
     * {@link org.webpki.jose.jws.JWSValidator#validate(JWSDecoder) validated}.
     * For JWS/CT this method return the JSON that is actually signed.  That is,
     * all but the 
    * {@link org.webpki.jose.jws.JWSDecoder#JWSDecoder(JSONObjectReader, String) signatureProperty}
     * and its JWS argument.
     * @return Payload as JSON
     */
    public JSONObjectReader getPayloadAsJson() {
        if (savedJWSCtObject == null) {
            return JSONParser.parse(getPayload());
        }
        checkValidation();
        return savedJWSCtObject;
    }
}

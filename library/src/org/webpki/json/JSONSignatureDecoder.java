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
package org.webpki.json;

import java.io.IOException;

import java.math.BigInteger;

import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPublicKeySpec;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.SignatureAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.OkpSupport;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyTypes;

import org.webpki.crypto.signatures.SignatureWrapper;

/**
 * Decoder for JSF signatures.
 */
public class JSONSignatureDecoder {

    SignatureAlgorithms signatureAlgorithm;

    String algorithmString;

    byte[] normalizedData;

    byte[] signatureValue;

    X509Certificate[] certificatePath;

    PublicKey publicKey;

    String keyId;
    
    JSONCryptoHelper.Options options;
    
    LinkedHashMap<String,JSONCryptoHelper.Extension> extensions = new LinkedHashMap<>();

    JSONSignatureDecoder(JSONObjectReader signedData,
                         JSONObjectReader innerSignatureObject,
                         JSONObjectReader outerSignatureObject,
                         JSONCryptoHelper.Options options) throws IOException,
                                                                  GeneralSecurityException {
        this.options = options;
        algorithmString = innerSignatureObject.getString(JSONCryptoHelper.ALGORITHM_JSON);
        keyId = options.getKeyId(innerSignatureObject);

        for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
            if (algorithmString.equals(
                    alg.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER)) ||
                    algorithmString.equals(alg.getAlgorithmId(AlgorithmPreferences.SKS))) {
                signatureAlgorithm = AsymSignatureAlgorithms.getAlgorithmFromId(
                        algorithmString, 
                        options.algorithmPreferences);
                if (innerSignatureObject.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH_JSON)) {
                    certificatePath = innerSignatureObject.getCertificatePath();
                    options.publicKeyOption.checkCertificatePath();
                } else if (innerSignatureObject.hasProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)) {
                    publicKey = innerSignatureObject.getPublicKey(options.algorithmPreferences);
                    options.publicKeyOption.checkPublicKey(keyId);
                } else {
                    options.publicKeyOption.checkMissingKey(keyId);
                }
                break;
            }
        }
        if (signatureAlgorithm == null) {
            signatureAlgorithm = 
                    HmacAlgorithms.getAlgorithmFromId(algorithmString, 
                                                      options.algorithmPreferences);
        }

        options.getExtensions(innerSignatureObject, outerSignatureObject, extensions);

        LinkedHashMap<String, JSONValue> saveExcluded = null;
        JSONValue saveExcludeArray = null;

        if (options.exclusions == null) {
            if (outerSignatureObject.hasProperty(JSONCryptoHelper.EXCLUDES_JSON)) {
                throw new IOException("Use of \"" + JSONCryptoHelper.EXCLUDES_JSON +
                                      "\" must be set in options");
            }
        } else {
            saveExcluded = new LinkedHashMap<>(signedData.root.properties);
            LinkedHashSet<String> parsedExcludes = 
                    checkExcluded(outerSignatureObject.getStringArray(
                            JSONCryptoHelper.EXCLUDES_JSON));
            for (String excluded : parsedExcludes.toArray(new String[0])) {
                if (!options.exclusions.contains(excluded)) {
                    throw new IOException("Unexpected \"" + JSONCryptoHelper.EXCLUDES_JSON + 
                                          "\" property: " + excluded);
                }
                if (!signedData.root.properties.containsKey(excluded)) {
                    throw new IOException("Excluded property \"" + excluded + "\" not found");
                }
                signedData.root.properties.remove(excluded);
            }
            for (String excluded : options.exclusions.toArray(new String[0])) {
                if (!parsedExcludes.contains(excluded)) {
                    throw new IOException("Missing \"" + JSONCryptoHelper.EXCLUDES_JSON +
                                          "\" property: " + excluded);
                }
            }
            // Hide the exclude property from the serializer...
            saveExcludeArray = outerSignatureObject.root.properties.get(
                    JSONCryptoHelper.EXCLUDES_JSON);
            outerSignatureObject.root.properties.put(JSONCryptoHelper.EXCLUDES_JSON, null);
        }

        signatureValue = innerSignatureObject.getBinary(JSONCryptoHelper.VALUE_JSON);

        //////////////////////////////////////////////////////////////////////////////////////
        // Begin JSF/JCS core data normalization                                            //
        //                                                                                  //
        // 1. Make a shallow copy of the signature object                                   //
        LinkedHashMap<String, JSONValue> savedProperties =                                  //
                new LinkedHashMap<>(innerSignatureObject.root.properties);                  //
        //                                                                                  //
        // 2. Hide the signature value property for the serializer...                       //
        innerSignatureObject.root.properties.remove(JSONCryptoHelper.VALUE_JSON);           //
        //                                                                                  //
        // 3. Serialize                                                                     //
        normalizedData = signedData.serializeToBytes(JSONOutputFormats.CANONICALIZED);      //
        //                                                                                  //
        // 4. Restore the signature object                                                  //
        innerSignatureObject.root.properties = savedProperties;                             //
        //                                                                                  //
        // End JSF/JCS core data normalization                                              //
        //////////////////////////////////////////////////////////////////////////////////////

        if (options.exclusions != null) {
            signedData.root.properties = saveExcluded;
            outerSignatureObject.root.properties.put(
                    JSONCryptoHelper.EXCLUDES_JSON, saveExcludeArray);
        }

        // Check for unread (=forbidden) data
        innerSignatureObject.checkForUnread();

        // Signatures with in-lined keys can be verified.  Note: verified <> trusted!
        if (certificatePath != null) {
            asymmetricSignatureVerification(certificatePath[0].getPublicKey());
        } else if (publicKey != null) {
            asymmetricSignatureVerification(publicKey);
        }
    }

    static BigInteger getCurvePoint(JSONObjectReader rd, 
                                    String property,
                                    KeyAlgorithms ec) throws IOException {
        byte[] fixedBinary = rd.getBinary(property);
        if (fixedBinary.length != (ec.getPublicKeySizeInBits() + 7) / 8) {
            throw new IOException("Public EC key parameter \"" + property + "\" is not normalized");
        }
        return new BigInteger(1, fixedBinary);
    }

    static BigInteger getCryptoBinary(JSONObjectReader rd, 
                                      String property) throws IOException {
        byte[] cryptoBinary = rd.getBinary(property);
        if (cryptoBinary[0] == 0x00) {
            throw new IOException("RSA key parameter \"" + 
                                  property + 
                                  "\" contains leading zeroes");
        }
        return new BigInteger(1, cryptoBinary);
    }

    static PublicKey decodePublicKey(JSONObjectReader rd,
                                     AlgorithmPreferences algorithmPreferences) throws IOException {
        PublicKey publicKey = null;
        try {
            String kty = rd.getString(JSONCryptoHelper.KTY_JSON);
            KeyAlgorithms keyAlgorithm;
            switch (kty) {
            case JSONCryptoHelper.RSA_PUBLIC_KEY:
                publicKey = KeyFactory.getInstance("RSA").generatePublic(
                        new RSAPublicKeySpec(getCryptoBinary(rd, JSONCryptoHelper.N_JSON),
                                             getCryptoBinary(rd, JSONCryptoHelper.E_JSON)));
                break;
            case JSONCryptoHelper.EC_PUBLIC_KEY:
                keyAlgorithm = KeyAlgorithms.getKeyAlgorithmFromId(
                        rd.getString(JSONCryptoHelper.CRV_JSON),
                        algorithmPreferences);
                if (keyAlgorithm.getKeyType() != KeyTypes.EC) {
                    throw new IllegalArgumentException("\"" + JSONCryptoHelper.CRV_JSON + 
                                                       "\" is not an EC type");
                }
                ECPoint w = new ECPoint(getCurvePoint(rd, JSONCryptoHelper.X_JSON, keyAlgorithm),
                                        getCurvePoint(rd, JSONCryptoHelper.Y_JSON, keyAlgorithm));
                publicKey = KeyFactory.getInstance("EC")
                        .generatePublic(new ECPublicKeySpec(w, keyAlgorithm.getECParameterSpec()));
                break;
            case JSONCryptoHelper.OKP_PUBLIC_KEY:
                keyAlgorithm = KeyAlgorithms.getKeyAlgorithmFromId(
                        rd.getString(JSONCryptoHelper.CRV_JSON),
                        algorithmPreferences);
                if (keyAlgorithm.getKeyType() != KeyTypes.EDDSA &&
                    keyAlgorithm.getKeyType() != KeyTypes.XEC) {
                    throw new IllegalArgumentException("\"" + JSONCryptoHelper.CRV_JSON + 
                                                       "\" is not a valid OKP type");
                }
                publicKey = OkpSupport.raw2PublicOkpKey(rd.getBinary(JSONCryptoHelper.X_JSON), 
                                                        keyAlgorithm);
                break;
            default:
                throw new IllegalArgumentException("Unrecognized \"" + 
                                                   JSONCryptoHelper.KTY_JSON + "\": " + kty);
            }
            return publicKey;
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    void asymmetricSignatureVerification(PublicKey publicKey) throws IOException {
        if (((AsymSignatureAlgorithms) signatureAlgorithm).getKeyType() !=
                KeyAlgorithms.getKeyAlgorithm(publicKey).getKeyType()) {
            throw new IllegalArgumentException("Algorithm \"" + algorithmString + 
                                  "\" doesn't match key type: " + publicKey.getAlgorithm());
        }
        try {
            if (!new SignatureWrapper((AsymSignatureAlgorithms) signatureAlgorithm, publicKey)
                         .update(normalizedData)
                         .verify(signatureValue)) {
                throw new IOException("Bad signature for key: " + publicKey.toString());
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    public byte[] getSignatureValue() {
        return signatureValue;
    }

    public SignatureAlgorithms getAlgorithm() {
        return signatureAlgorithm;
    }

    public JSONCryptoHelper.Extension getExtension(String name) {
        return extensions.get(name);
    }

    void checkRequest(JSONSignatureTypes signatureType) throws IOException {
        if (signatureType != getSignatureType()) {
            throw new IOException("Request doesn't match received signature: " + 
                                  getSignatureType().toString());
        }
    }

    public X509Certificate[] getCertificatePath() throws IOException {
        checkRequest(JSONSignatureTypes.X509_CERTIFICATE);
        return certificatePath;
    }

    public PublicKey getPublicKey() throws IOException {
        checkRequest(JSONSignatureTypes.ASYMMETRIC_KEY);
        return publicKey;
    }

    public String getKeyId() {
        return keyId;
    }

    public byte[] getNormalizedData() {
        return normalizedData;
    }

    public JSONSignatureTypes getSignatureType() {
        if (certificatePath != null) {
            return JSONSignatureTypes.X509_CERTIFICATE;
        }
        return signatureAlgorithm instanceof AsymSignatureAlgorithms ? 
                          JSONSignatureTypes.ASYMMETRIC_KEY : JSONSignatureTypes.SYMMETRIC_KEY;
    }

    public void verify(JSONVerifier verifier) throws IOException, GeneralSecurityException {
        checkRequest(verifier.signatureType);
        verifier.verify(this);
    }

    static PrivateKey decodePrivateKey(JSONObjectReader rd,
                                       PublicKey publicKey) throws IOException {
        try {
            KeyAlgorithms keyAlgorithm = KeyAlgorithms.getKeyAlgorithm(publicKey);
            switch (keyAlgorithm.getKeyType()) {
            case EC:
                return KeyFactory.getInstance("EC").generatePrivate(
                        new ECPrivateKeySpec(getCurvePoint(rd, "d", keyAlgorithm),
                                             keyAlgorithm.getECParameterSpec()));
            case RSA:
                return KeyFactory.getInstance("RSA").generatePrivate(
                        new RSAPrivateCrtKeySpec(((RSAPublicKey) publicKey).getModulus(),
                                                 ((RSAPublicKey) publicKey).getPublicExponent(),
                                                 getCryptoBinary(rd, "d"),
                                                 getCryptoBinary(rd, "p"),
                                                 getCryptoBinary(rd, "q"),
                                                 getCryptoBinary(rd, "dp"),
                                                 getCryptoBinary(rd, "dq"),
                                                 getCryptoBinary(rd, "qi")));
            default:
                return OkpSupport.raw2PrivateOkpKey(rd.getBinary("d"), keyAlgorithm);
            }
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }

    static LinkedHashSet<String> checkExcluded(String[] excluded) throws IOException {
        if (excluded.length == 0) {
            throw new IOException("Empty \"" + 
                                  JSONCryptoHelper.EXCLUDES_JSON + "\" array not allowed");
        }
        LinkedHashSet<String> ex = new LinkedHashSet<>();
        for (String property : excluded) {
            if (!ex.add(property)) {
                throw new IOException("Duplicate \"" + 
                                      JSONCryptoHelper.EXCLUDES_JSON + "\" property: " + property);
            }
        }
        return ex;
    }
}

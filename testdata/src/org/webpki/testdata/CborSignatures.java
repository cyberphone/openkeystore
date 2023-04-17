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
package org.webpki.testdata;

import java.io.File;
import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAKey;

import java.util.Arrays;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORTag;
import org.webpki.cbor.CBORTest;
import org.webpki.cbor.CBORString;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORFloatingPoint;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORCryptoUtils;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyTypes;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONParser;

// Test
import org.webpki.json.SymmetricKeys;

import org.webpki.util.HexaDecimal;
import org.webpki.util.IO;
import org.webpki.util.PEMDecoder;
import org.webpki.util.UTF8;

/*
 * Create CSF test vectors
 */
public class CborSignatures {
    static String baseKey;
    static String baseData;
    static String baseSignatures;
    static SymmetricKeys symmetricKeys;
    static CBORObject keyId;
    
    static final CBORString SIGNATURE_LABEL = new CBORString("signature");
    

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new Exception("Wrong number of arguments");
        }
        CustomCryptoProvider.forcedLoad(false);
        baseKey = args[0] + File.separator;
        baseData = args[1] + File.separator;
        baseSignatures = args[2] + File.separator;
        symmetricKeys = new SymmetricKeys(baseKey);
        

        for (String key : new String[]{"p256", "p384", "p521", "r2048", "ed25519", "ed448"}) {
            // Check the PEM reader
            KeyPair keyPairPem = new KeyPair(
                PEMDecoder.getPublicKey(IO.readFile(baseKey + key + "publickey.pem")),
                PEMDecoder.getPrivateKey(IO.readFile(baseKey + key + "privatekey.pem")));
            X509Certificate[] certificatePath = 
                PEMDecoder.getCertificatePath(IO.readFile(baseKey + key + "certpath.pem"));
            KeyPair keyPairJwk = readJwk(key);
            if (!keyPairJwk.getPublic().equals(keyPairPem.getPublic())) {
                throw new IOException("PEM fail at public " + key);
            }
            if (!keyPairJwk.getPrivate().equals(keyPairPem.getPrivate())) {
                throw new IOException("PEM fail at private " + key);
            }
            KeyStore keyStorePem = 
                    PEMDecoder.getKeyStore(IO.readFile(baseKey + key + "certificate-key.pem"),
                                                              "mykey", "foo123");
            if (!keyPairJwk.getPrivate().equals(keyStorePem.getKey("mykey",
                                                                   "foo123".toCharArray()))) {
                throw new IOException("PEM KS fail at private " + key);
            }
            if (!keyPairJwk.getPublic().equals(keyStorePem.getCertificate("mykey").getPublicKey())) {
                throw new IOException("PEM KS fail at public " + key);
            }
            asymKeyAllVariations(key, null);
            if (keyPairJwk.getPublic() instanceof RSAKey) {
                for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
                    if (alg.getMGF1ParameterSpec() != null) {
                        asymKeyAllVariations(key, alg);
                    }
                }
            }
            certSignCore(key, keyPairPem, certificatePath);
        }
      
        for (int i = 0; i < 2; i++) {
            symKeySign(256, HmacAlgorithms.HMAC_SHA256, i == 0);
            symKeySign(384, HmacAlgorithms.HMAC_SHA384, i == 0);
            symKeySign(512, HmacAlgorithms.HMAC_SHA512, i == 0);
        }
        
        asymSignCore("p256",    false, true, 1, false, null);
        asymSignCore("ed25519", false, true, 2, false, null);
        asymSignCore("ed25519", false, true, 0, true,  null);
        asymSignCore("ed25519", false, true, 2, true,  null);
        asymSignCore("p256",    false, true, 2, true,  null);
        
        demoDocSignature(baseSignatures + "demo-doc-signature.cbor");
    }
    
    static void asymKeyAllVariations(String key, AsymSignatureAlgorithms pssAlg) throws Exception {
        asymSignCore(key, false, false, 0, false, pssAlg);
        asymSignCore(key, false, true,  0, false, pssAlg);
        asymSignCore(key, true,  false, 0, false, pssAlg);
   }

    static String prefix(String keyType) {
        return keyType + '#';
    }
    
    static String cleanSignature(byte[] csfData) throws IOException {
        CBORObject signedObject = CBORObject.decode(csfData); 
        CBORMap decoded = CborEncryption.unwrapOptionalTag(signedObject);
        CBORObject[] keys = decoded.getMap().getKeys();
        for (CBORObject key : keys) {
            CBORObject value = decoded.getMap().getObject(key);
            if (value.getType() == CBORTypes.MAP) {
                CBORMap possibleSignature = value.getMap();
                if (possibleSignature.hasKey(CBORCryptoConstants.ALGORITHM_LABEL)) {
                    CBORObject alg =
                            possibleSignature.getObject(CBORCryptoConstants.ALGORITHM_LABEL);
                    if (alg.getType() != CBORTypes.INTEGER) continue;
                }
                if (possibleSignature.hasKey(CBORCryptoConstants.SIGNATURE_LABEL)) {
                    CBORObject sig =
                            possibleSignature.getObject(CBORCryptoConstants.SIGNATURE_LABEL);
                    if (sig.getType() != CBORTypes.BYTE_STRING) continue;
                }
                // This is with 99% certainty a CSF signature.  Bump the signature value.
                possibleSignature.removeObject(CBORCryptoConstants.SIGNATURE_LABEL);
                return signedObject.toString();
            }
        }
        throw new IOException("Signature not found");
    }
    
    static void optionalUpdate(CBORValidator validator,
                               String fileName, 
                               byte[] updatedSignature, 
                               boolean cleanFlag) throws Exception {
        boolean changed = true;
        byte[] oldSignature = null;
        try {
            oldSignature = IO.readFile(fileName);
            try {
                validator.validate(SIGNATURE_LABEL, CBORObject.decode(oldSignature));
            } catch (Exception e) {
                throw new GeneralSecurityException(
                        "ERROR - Old signature '" + fileName + "' did not validate");
            }
        } catch (IOException e) {
            changed = false;  // New file
        }
        if (oldSignature != null) {
            if (cleanFlag) {
                if (cleanSignature(oldSignature).equals(cleanSignature(updatedSignature))) {
                    return;
                }
            } else {
                if (Arrays.equals(oldSignature, updatedSignature)) {
                    return;
                }
            }
        }
        IO.writeFile(fileName, updatedSignature);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
        return;
    }

    static void symKeySign(int keyBits, 
                           HmacAlgorithms algorithm, 
                           boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        CBORObject keyName = new CBORString(symmetricKeys.getName(keyBits));
        CBORHmacSigner signer = new CBORHmacSigner(key, algorithm);
        if (wantKeyId) {
            signer.setKeyId(keyName);
        }
        byte[] signedData = createSignature(signer);
        CBORHmacValidator validator = new CBORHmacValidator(key);
        CBORMap decoded = CBORObject.decode(signedData).getMap();
        validator.validate(SIGNATURE_LABEL, decoded);
        new CBORHmacValidator(new CBORHmacValidator.KeyLocator() {
            
            @Override
            public byte[] locate(CBORObject optionalKeyId, HmacAlgorithms hmacAlgorithm)
                    throws IOException, GeneralSecurityException {
                if (wantKeyId && !CBORTest.compareKeyId(keyName, optionalKeyId)) {
                    throw new GeneralSecurityException("No id");
                }
                if (!algorithm.equals(hmacAlgorithm)) {
                    throw new GeneralSecurityException("Bad algorithm");
                }
                return key;
            }

        }).validate(SIGNATURE_LABEL, decoded);
        optionalUpdate(validator, 
                       baseSignatures + prefix("a" + keyBits) + 
                           getAlgorithm(algorithm) + '@' + keyIndicator(wantKeyId, 
                                                                        false,
                                                                        0,
                                                                        false),
                       signedData,
                       false);
    }

    static byte[] getDataToSign() throws Exception {
        return new CBORMap()
            .setObject(new CBORString("instant"), new CBORString("2021-06-10T11:23:06Z"))
            .setObject(new CBORString("name"), new CBORString("John Doe"))
            .setObject(new CBORString("id"), new CBORInteger(123456))
            .encode();
    }
    
    static CBORMap parseDataToSign() throws Exception {
        return CBORObject.decode(getDataToSign()).getMap();
    }

    static byte[] createSignature(CBORSigner signer) throws Exception {
        return signer.sign(SIGNATURE_LABEL, parseDataToSign()).encode();
    }
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(IO.readFile(
                baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it
        // doesn't have a meaning in JSF or JEF. 
        keyId = new CBORString(jwkPlus.getString("kid"));
        jwkPlus.removeProperty("kid");
        return jwkPlus.getKeyPair();
    }
    
    
    static String keyIndicator(boolean wantKeyId, 
                               boolean wantPublicKey, 
                               int tagged, 
                               boolean customData) {
        return (tagged == 1 ? "tag1Dim." : tagged == 2 ? "tag2Dim." : "") + 
               (customData ? "custom." : "") +
               (wantKeyId ? "kid" : wantPublicKey ? "pub" : "imp") + ".cbor";
    }
    
    static String getAlgorithm(SignatureAlgorithms algorithm) throws IOException {
        return algorithm.getJoseAlgorithmId().toLowerCase();
    }
    
    static class SaveAlgorithm {
        AsymSignatureAlgorithms algorithm;
    }
 
    static void certSignCore(String keyType, KeyPair keyPair, X509Certificate[] certificatePath)
            throws Exception {
        CBORX509Signer signer = new CBORX509Signer(keyPair.getPrivate(), certificatePath);
        byte[] signedData = createSignature(signer);
        final SaveAlgorithm saveAlgorithm = new SaveAlgorithm();
        CBORX509Validator validator = new CBORX509Validator(
            new CBORX509Validator.Parameters() {

                @Override
                public void verify(X509Certificate[] certificatePath,
                                   AsymSignatureAlgorithms asymSignatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    saveAlgorithm.algorithm = asymSignatureAlgorithm;
                }
                
            });
        CBORObject decoded = CBORObject.decode(signedData);
        validator.validate(SIGNATURE_LABEL, decoded);
        String fileName = baseSignatures + prefix(keyType)
                + getAlgorithm(saveAlgorithm.algorithm) + "@cer.cbor";
        new CBORX509Validator(new CBORX509Validator.Parameters() {

            @Override
            public void verify(X509Certificate[] certificatePath,
                               AsymSignatureAlgorithms asymSignatureAlgorithm)
                    throws IOException, GeneralSecurityException {
            }
            
        }).validate(SIGNATURE_LABEL, decoded);
        optionalUpdate(validator, fileName, signedData, 
                saveAlgorithm.algorithm.getKeyType() == KeyTypes.EC);
    }

    static void asymSignCore(String keyType, 
                             boolean wantKeyId,
                             boolean wantPublicKey,
                             int tagged,
                             boolean customData,
                             AsymSignatureAlgorithms pssAlg) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        final AsymSignatureAlgorithms algorithm = pssAlg == null ? 
                KeyAlgorithms.getKeyAlgorithm(
                        keyPair.getPublic()).getRecommendedSignatureAlgorithm() : pssAlg;
       CBORAsymKeySigner signer = pssAlg == null ?
                new CBORAsymKeySigner(keyPair.getPrivate())
                                                 :
                new CBORAsymKeySigner(keyPair.getPrivate(), pssAlg);
        if (wantKeyId) {
            signer.setKeyId(keyId);
        }
        if (wantPublicKey) {
            signer.setPublicKey(keyPair.getPublic());
        }
        if (tagged != 0) {
            signer.setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject wrap(CBORMap mapToSign) 
                        throws IOException, GeneralSecurityException {
                    
                    // 1-dimensional or 2-dimensional tag
                    return tagged == 1 ?
                            new CBORTag(CborEncryption.NON_RESEVED_TAG, mapToSign)
                                       :
                            new CBORTag("https://example.com/myobject", mapToSign);
                }
                
                @Override
                public CBORObject getCustomData() throws IOException, GeneralSecurityException {
                    return customData ? CborEncryption.CUSTOM_DATA : null;
                }                
            });
        } else if (customData ) {
            signer.setIntercepter(new CBORCryptoUtils.Intercepter() {
                
                @Override
                public CBORObject getCustomData() throws IOException, GeneralSecurityException {
                    return CborEncryption.CUSTOM_DATA;
                }     
                
            });
        }
        byte[] signedData = createSignature(signer);
        CBORAsymKeyValidator validator = new CBORAsymKeyValidator(keyPair.getPublic());
        if (tagged != 0) {
            validator.setTagPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                    new CBORCryptoUtils.Collector() {
                        
                        @Override
                        public void foundData(CBORObject wrapperTafg)
                                throws IOException, GeneralSecurityException {
                            CborEncryption.verifyTag(wrapperTafg);
                        }
                    });
        }
        if (customData) {
            validator.setCustomDataPolicy(CBORCryptoUtils.POLICY.MANDATORY,
                    new CBORCryptoUtils.Collector() {
                        
                        @Override
                        public void foundData(CBORObject customData)
                                throws IOException, GeneralSecurityException {
                            customData.getString();
                        }
                    });
        }
        CBORObject decoded = CBORObject.decode(signedData);
        validator.validate(SIGNATURE_LABEL, decoded);
        String fileName = baseSignatures + prefix(keyType) +
                getAlgorithm(algorithm) + '@' +  
                keyIndicator(wantKeyId, wantPublicKey, tagged, customData);
        CBORCryptoUtils.Collector tagCollector = null;
        CBORCryptoUtils.POLICY tagPolicy = CBORCryptoUtils.POLICY.FORBIDDEN;
        if (tagged != 0) {
            tagPolicy = CBORCryptoUtils.POLICY.MANDATORY;
            tagCollector = new CBORCryptoUtils.Collector() {

                @Override
                public void foundData(CBORObject wrapperTag)
                        throws IOException, GeneralSecurityException {
                    CborEncryption.verifyTag(wrapperTag);
                }
                
            };
        }
        CBORCryptoUtils.Collector customDataCollector = null;
        CBORCryptoUtils.POLICY customDataPolicy = CBORCryptoUtils.POLICY.FORBIDDEN;
        if (customData) {
            customDataPolicy = CBORCryptoUtils.POLICY.MANDATORY;
            customDataCollector = new CBORCryptoUtils.Collector() {

                @Override
                public void foundData(CBORObject customData)
                        throws IOException, GeneralSecurityException {
 
                }
                
            };
        }
        new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {
            
            @Override
            public PublicKey locate(PublicKey optionalPublicKey, 
                                    CBORObject optionalKeyId, 
                                    AsymSignatureAlgorithms arg2)
                    throws IOException, GeneralSecurityException {
                if (wantPublicKey && !keyPair.getPublic().equals(optionalPublicKey)) {
                    throw new GeneralSecurityException("Missing public key");
                }
                if (wantKeyId && !CBORTest.compareKeyId(keyId, optionalKeyId)) {
                    throw new GeneralSecurityException("Missing key Id");
                }
                if (algorithm != arg2) {
                    throw new GeneralSecurityException("Missing algorithm");
                }
                return keyPair.getPublic();
            }
        }).setTagPolicy(tagPolicy, tagCollector)
          .setCustomDataPolicy(customDataPolicy, customDataCollector)
          .validate(SIGNATURE_LABEL, decoded);
        optionalUpdate(validator, fileName, signedData, 
                algorithm.getMGF1ParameterSpec() != null ||
                algorithm.getKeyType() == KeyTypes.EC);
    }

    static void demoDocSignature(String fileName) throws Exception {
        KeyPair keyPair = readJwk("p256");
        CBORAsymKeySigner signer = 
                new CBORAsymKeySigner(keyPair.getPrivate()).setPublicKey(keyPair.getPublic());
        byte[] signedData = signer.sign(new CBORInteger(-1), 
                new CBORMap().setObject(new CBORInteger(1), 
                                        new CBORMap()
                                            .setObject(new CBORInteger(1), new CBORString("Space Shop"))
                                            .setObject(new CBORInteger(2), new CBORString("435.00"))
                                            .setObject(new CBORInteger(3), new CBORString("USD")))
                             .setObject(new CBORInteger(2), new CBORString("spaceshop.com"))
                             .setObject(new CBORInteger(3), new CBORString("FR7630002111110020050014382"))
                             .setObject(new CBORInteger(4), new CBORString("https://banknet2.org"))
                             .setObject(new CBORInteger(5), new CBORString("05768401"))
                             .setObject(new CBORInteger(6), new CBORString("2022-09-29T09:34:08-05:00"))
                             .setObject(new CBORInteger(7),
                                        new CBORMap()
                                            .setObject(new CBORInteger(1), new CBORFloatingPoint(38.8882))
                                            .setObject(new CBORInteger(2), new CBORFloatingPoint(77.0199))))
                .encode();
        CBORAsymKeyValidator validator = new CBORAsymKeyValidator(keyPair.getPublic());
        boolean changed = true;
        byte[] oldSignature = null;
        try {
            oldSignature = IO.readFile(fileName);
            try {
                validator.validate(new CBORInteger(-1), CBORObject.decode(oldSignature).getMap());
            } catch (Exception e) {
                throw new GeneralSecurityException(
                        "ERROR - Old signature '" + fileName + "' did not validate");
            }
        } catch (IOException e) {
            changed = false;  // New file
        }
        if (oldSignature != null) {
            if (cleanSignature(oldSignature).equals(cleanSignature(signedData))) {
                additionalFiles(fileName, oldSignature);
                return;
            }

        }
        IO.writeFile(fileName, signedData);
        additionalFiles(fileName, signedData);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
    }

    private static void additionalFiles(String fileName, byte[] signature) throws IOException {
        IO.writeFile(fileName.replace(".cbor", ".hex"), 
                            UTF8.encode(HexaDecimal.encode(signature)));
        StringBuilder text = new StringBuilder(CBORObject.decode(signature).toString());
        int i = text.indexOf("\n  -1:");
        for (String comment : new String[]{"Enveloped signature object",
                                           "Signature algorithm = ES256",
                                           "Public key descriptor in COSE format",
                                           "kty = EC",
                                           "crv = P-256",
                                           "x",
                                           "y",
                                           "Signature value"}) {
            while (true) {
                int spaces = 0;
                while (text.charAt(++i) == ' ') {
                    spaces++;
                };
                if (text.charAt(i) == '}') {
                    i = text.indexOf("\n", i);
                    continue;
                }
                text.insert(i - spaces, "<div style='height:0.5em'></div>");
                i += 32;
                for (int q = 0; q < spaces; q++) {
                    text.insert(i - spaces, ' ');
                }
                String added = "<span style='color:grey'>/ " + comment + " /</span>\n";
                text.insert(i, added);
                i = text.indexOf("\n", i + added.length() + spaces);
                break;
            }
        }
        IO.writeFile(fileName.replace(".cbor", ".txt"), 
                            UTF8.encode(text.toString()
                                .replace("6: h'", "<span class='webpkihighlite'>6: h'")
                                .replace("'\n  }\n}", "'</span>\n  }\n}")
                                .replace("\n", "<br>\n")
                                .replace("  ", "&nbsp;&nbsp;")));
    }

}
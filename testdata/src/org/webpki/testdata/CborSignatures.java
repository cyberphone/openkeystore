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

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORTest;
import org.webpki.cbor.CBORTextString;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORValidator;
import org.webpki.cbor.CBORX509Signer;
import org.webpki.cbor.CBORX509Validator;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORDouble;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORMap;

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

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

/*
 * Create JSF test vectors
 */
public class CborSignatures {
    static String baseKey;
    static String baseData;
    static String baseSignatures;
    static SymmetricKeys symmetricKeys;
    static byte[] keyId;
    
    static final String SIGNATURE_LABEL = "signature";
    

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
                PEMDecoder.getPublicKey(ArrayUtil.readFile(baseKey + key + "publickey.pem")),
                PEMDecoder.getPrivateKey(ArrayUtil.readFile(baseKey + key + "privatekey.pem")));
            X509Certificate[] certificatePath = 
                PEMDecoder.getCertificatePath(ArrayUtil.readFile(baseKey + key + "certpath.pem"));
            KeyPair keyPairJwk = readJwk(key);
            if (!keyPairJwk.getPublic().equals(keyPairPem.getPublic())) {
                throw new IOException("PEM fail at public " + key);
            }
            if (!keyPairJwk.getPrivate().equals(keyPairPem.getPrivate())) {
                throw new IOException("PEM fail at private " + key);
            }
            KeyStore keyStorePem = 
                    PEMDecoder.getKeyStore(ArrayUtil.readFile(baseKey + key + "certificate-key.pem"),
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
        
        demoDocSignature(baseSignatures + "demo-doc-signature.cbor");
    }
    
    static void asymKeyAllVariations(String key, AsymSignatureAlgorithms pssAlg) throws Exception {
        asymSignCore(key, false, false, pssAlg);
        asymSignCore(key, false, true,  pssAlg);
        asymSignCore(key, true,  false, pssAlg);
   }

    static String prefix(String keyType) {
        return keyType + '#';
    }
    
    static String cleanSignature(byte[] csfData) throws IOException {
        CBORObject decoded = CBORObject.decode(csfData);
        CBORObject[] keys = decoded.getMap().getKeys();
        for (CBORObject key : keys) {
            CBORObject value = decoded.getMap().getObject(key);
            if (value.getType() == CBORTypes.MAP) {
                CBORMap possibleSignature = value.getMap();
                if (possibleSignature.hasKey(CBORSigner.ALGORITHM_LABEL)) {
                    CBORObject alg =
                            possibleSignature.getObject(CBORSigner.ALGORITHM_LABEL);
                    if (alg.getType() != CBORTypes.INTEGER) continue;
                }
                if (possibleSignature.hasKey(CBORSigner.SIGNATURE_LABEL)) {
                    CBORObject sig =
                            possibleSignature.getObject(CBORSigner.SIGNATURE_LABEL);
                    if (sig.getType() != CBORTypes.BYTE_STRING) continue;
                }
                // This is with 99% certainty a CSF signature.  Bump the signature value.
                possibleSignature.removeObject(CBORSigner.SIGNATURE_LABEL);
                return decoded.toString();
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
            oldSignature = ArrayUtil.readFile(fileName);
            try {
                CBORObject.decode(oldSignature).getMap().validate(SIGNATURE_LABEL, validator);
            } catch (Exception e) {
                throw new GeneralSecurityException("ERROR - Old signature '" + fileName + "' did not validate");
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
                if (ArrayUtil.compare(oldSignature, updatedSignature)) {
                    return;
                }
            }
        }
        ArrayUtil.writeFile(fileName, updatedSignature);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
        return;
    }

    static void symKeySign(int keyBits, HmacAlgorithms algorithm, boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        byte[] keyName = symmetricKeys.getName(keyBits).getBytes("utf-8");
        CBORHmacSigner signer = new CBORHmacSigner(key, algorithm);
        if (wantKeyId) {
            signer.setKeyId(keyName);
        }
        byte[] signedData = createSignature(signer);
        CBORHmacValidator validator = new CBORHmacValidator(key);
        CBORMap decoded = CBORObject.decode(signedData).getMap();
        decoded.validate(SIGNATURE_LABEL, validator);
        decoded.validate(SIGNATURE_LABEL, new CBORHmacValidator(new CBORHmacValidator.KeyLocator() {
            
            @Override
            public byte[] locate(byte[] optionalKeyId, HmacAlgorithms arg1)
                    throws IOException, GeneralSecurityException {
                if (wantKeyId && !CBORTest.compareKeyId(keyName, optionalKeyId)) {
                    throw new GeneralSecurityException("No id");
                }
                if (!algorithm.equals(arg1)) {
                    throw new GeneralSecurityException("Bad algorithm");
                }
                return key;
            }

        }));
        optionalUpdate(validator, 
                       baseSignatures + prefix("a" + keyBits) + 
                           getAlgorithm(algorithm) + '@' + keyIndicator(wantKeyId, false),
                       signedData,
                       false);
    }

    static byte[] getDataToSign() throws Exception {
        return new CBORMap()
            .setObject("instant", new CBORTextString("2021-06-10T11:23:06Z"))
            .setObject("name", new CBORTextString("John Doe"))
            .setObject("id", new CBORInteger(123456))
            .encode();
    }
    
    static CBORMap parseDataToSign() throws Exception {
        return CBORObject.decode(getDataToSign()).getMap();
    }

    static byte[] createSignature(CBORSigner signer) throws Exception {
        return parseDataToSign().sign(SIGNATURE_LABEL, signer).encode();
    }
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        keyId = jwkPlus.getString("kid").getBytes("utf-8");
        jwkPlus.removeProperty("kid");
        return jwkPlus.getKeyPair();
    }
    
    
    static String keyIndicator(boolean wantKeyId, boolean wantPublicKey) {
        return (wantKeyId ? (wantPublicKey ? "pub+kid" : "kid") : wantPublicKey ? "pub" : "imp") + ".cbor";
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
            new CBORX509Validator.SignatureParameters() {

                @Override
                public void check(X509Certificate[] certificatePath,
                                  AsymSignatureAlgorithms asymSignatureAlgorithm)
                        throws IOException, GeneralSecurityException {
                    saveAlgorithm.algorithm = asymSignatureAlgorithm;
                }
                
            });
        CBORMap decoded = CBORObject.decode(signedData).getMap();
        decoded.validate(SIGNATURE_LABEL, validator);
        String fileName = baseSignatures + prefix(keyType)
                + getAlgorithm(saveAlgorithm.algorithm) + "@cer.cbor";
        decoded.validate(SIGNATURE_LABEL, new CBORX509Validator(
                new CBORX509Validator.SignatureParameters() {

            @Override
            public void check(X509Certificate[] certificatePath,
                              AsymSignatureAlgorithms asymSignatureAlgorithm)
                    throws IOException, GeneralSecurityException {
            }
            
        }));
        optionalUpdate(validator, fileName, signedData, 
                saveAlgorithm.algorithm.getKeyType() == KeyTypes.EC);
    }

    static void asymSignCore(String keyType, 
                             boolean wantKeyId,
                             boolean wantPublicKey,
                             AsymSignatureAlgorithms pssAlg) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        CBORAsymKeySigner signer = 
                new CBORAsymKeySigner(keyPair.getPrivate());
        final AsymSignatureAlgorithms algorithm = pssAlg == null ? 
                KeyAlgorithms.getKeyAlgorithm(
                        keyPair.getPublic()).getRecommendedSignatureAlgorithm() : pssAlg;
        if (pssAlg != null) {
            signer.setAlgorithm(pssAlg);
        }
        if (wantKeyId) {
            signer.setKeyId(keyId);
        }
        if (wantPublicKey) {
            signer.setPublicKey(keyPair.getPublic());
        }
        byte[] signedData = createSignature(signer);
        CBORAsymKeyValidator validator = new CBORAsymKeyValidator(keyPair.getPublic());
        CBORMap decoded = CBORObject.decode(signedData).getMap();
        decoded.validate(SIGNATURE_LABEL, validator);
        String fileName = baseSignatures + prefix(keyType) +
                getAlgorithm(algorithm) + '@' +  
                keyIndicator(wantKeyId, wantPublicKey);
        decoded.validate(SIGNATURE_LABEL, new CBORAsymKeyValidator(
                new CBORAsymKeyValidator.KeyLocator() {
            
            @Override
            public PublicKey locate(PublicKey arg0, 
                                    byte[] optionalKeyId, 
                                    AsymSignatureAlgorithms arg2)
                    throws IOException, GeneralSecurityException {
                if (wantPublicKey && !keyPair.getPublic().equals(arg0)) {
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
        }));
        optionalUpdate(validator, fileName, signedData, 
                algorithm.getMGF1ParameterSpec() != null ||
                algorithm.getKeyType() == KeyTypes.EC);
    }

    static void demoDocSignature(String fileName) throws Exception {
        KeyPair keyPair = readJwk("p256");
        CBORAsymKeySigner signer = 
                new CBORAsymKeySigner(keyPair.getPrivate()).setPublicKey(keyPair.getPublic());
        byte[] signedData =
                new CBORMap().setObject(1, 
                                        new CBORMap()
                                            .setObject(1, new CBORTextString("Space Shop"))
                                            .setObject(2, new CBORTextString("435.00"))
                                            .setObject(3, new CBORTextString("USD")))
                             .setObject(2, new CBORTextString("spaceshop.com"))
                             .setObject(3, new CBORTextString("FR7630002111110020050014382"))
                             .setObject(4, new CBORTextString("https://bankdirect.org"))
                             .setObject(5, new CBORTextString("05768401"))
                             .setObject(6, new CBORTextString("2022-01-14T09:34:08-05:00"))
                             .setObject(7,
                                        new CBORMap()
                                            .setObject(1, new CBORDouble(38.8882))
                                            .setObject(2, new CBORDouble(77.0199)))
                .sign(8, signer).encode();
        CBORAsymKeyValidator validator = new CBORAsymKeyValidator(keyPair.getPublic());
        boolean changed = true;
        byte[] oldSignature = null;
        try {
            oldSignature = ArrayUtil.readFile(fileName);
            try {
                CBORObject.decode(oldSignature).getMap().validate(8, validator);
            } catch (Exception e) {
                throw new GeneralSecurityException("ERROR - Old signature '" + fileName + "' did not validate");
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
        ArrayUtil.writeFile(fileName, signedData);
        additionalFiles(fileName, signedData);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
    }

    private static void additionalFiles(String fileName, byte[] signature) throws IOException {
        ArrayUtil.writeFile(fileName.replace(".cbor", ".hex"), 
                            DebugFormatter.getHexString(signature).getBytes("utf-8"));
        StringBuilder text = new StringBuilder(CBORObject.decode(signature).toString());
        int i = text.indexOf("\n  8:");
        for (String comment : new String[]{"Signature object",
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
                String added = "<span style='color:grey'>// " + comment + "</span>\n";
                text.insert(i, added);
                i = text.indexOf("\n", i + added.length() + spaces);
                break;
            }
        }
        ArrayUtil.writeFile(fileName.replace(".cbor", ".txt"), 
                            text.toString()
                                .replace("\n", "<br>\n")
                                .replace("  ", "&nbsp;&nbsp;").getBytes("utf-8"));
    }

}
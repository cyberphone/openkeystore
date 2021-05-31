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
import java.security.interfaces.RSAKey;

import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORTextString;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORTextStringMap;
import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORAsymSignatureValidator;
import org.webpki.cbor.CBORDateTime;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORInteger;
import org.webpki.cbor.CBORIntegerMap;

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
import org.webpki.util.PEMDecoder;

/*
 * Create JSF test vectors
 */
public class CborSignatures {
    static String baseKey;
    static String baseData;
    static String baseSignatures;
    static SymmetricKeys symmetricKeys;
    static String keyId;
    
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
            KeyPair keyPairPem = 
                    new KeyPair(PEMDecoder.getPublicKey(ArrayUtil.readFile(baseKey + key + "publickey.pem")),
                                PEMDecoder.getPrivateKey(ArrayUtil.readFile(baseKey + key + "privatekey.pem")));
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
        }
      
        for (int i = 0; i < 2; i++) {
            symmSign(256, HmacAlgorithms.HMAC_SHA256, i == 0);
            symmSign(384, HmacAlgorithms.HMAC_SHA384, i == 0);
            symmSign(512, HmacAlgorithms.HMAC_SHA512, i == 0);
        }
    }
    
    static void asymKeyAllVariations(String key, AsymSignatureAlgorithms pssAlg) throws Exception {
        asymSignCore(key, false, false, pssAlg);
        asymSignCore(key, false, true, pssAlg);
        asymSignCore(key, true, true, pssAlg);
   }

    static String prefix(String keyType) {
        return keyType + '#';
    }
    
    static String cleanSignature(byte[] csfData) throws IOException {
        CBORObject decoded = CBORObject.decode(csfData);
        String[] keys = decoded.getTextStringMap().getKeys();
        for (String key : keys) {
            CBORObject value = decoded.getTextStringMap().getObject(key);
            if (value.getType() == CBORTypes.INTEGER_MAP) {
                CBORIntegerMap possibleSignature = value.getIntegerMap();
                if (possibleSignature.hasKey(CBORSigner.ALGORITHM_LABEL.getInt())) {
                    CBORObject alg =
                            possibleSignature.getObject(CBORSigner.ALGORITHM_LABEL.getInt());
                    if (alg.getType() != CBORTypes.INTEGER) continue;
                }
                if (possibleSignature.hasKey(CBORSigner.SIGNATURE_LABEL.getInt())) {
                    CBORObject sig =
                            possibleSignature.getObject(CBORSigner.SIGNATURE_LABEL.getInt());
                    if (sig.getType() != CBORTypes.BYTE_STRING) continue;
                }
                // This is with 99% certainty a CSF signature.  Bump the signature value.
                possibleSignature.removeObject(CBORSigner.SIGNATURE_LABEL.getInt());
                return decoded.toString();
            }
        }
        throw new IOException("Signature not found");
    }
    
    static void optionalUpdate(String fileName, byte[] updatedSignature, boolean cleanFlag) throws IOException {
        boolean changed = true;
        try {
            if (cleanFlag) {
                if (cleanSignature(ArrayUtil.readFile(fileName)).equals(cleanSignature(updatedSignature))) {
                    return;
                }
            } else {
                if (ArrayUtil.compare(ArrayUtil.readFile(fileName), updatedSignature)) {
                    return;
                }
            }
        } catch (Exception e) {
            // New I guess.
            changed = false;
        }
        ArrayUtil.writeFile(fileName, updatedSignature);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
        return;
    }

    static void symmSign(int keyBits, HmacAlgorithms algorithm, boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        CBORHmacSigner signer = new CBORHmacSigner(key, algorithm);
        if (wantKeyId) {
            signer.setKeyId(keyName);
        }
        byte[] signedData = createSignature(signer);
        CBORHmacValidator validator = new CBORHmacValidator(key);
        CBORTextStringMap decoded = CBORObject.decode(signedData).getTextStringMap();
        decoded.validate(SIGNATURE_LABEL, validator);
        if (wantKeyId) {
            decoded.validate(SIGNATURE_LABEL, new CBORHmacValidator(
                    new CBORHmacValidator.KeyLocator() {
                
                @Override
                public byte[] locate(String arg0, HmacAlgorithms arg1)
                        throws IOException, GeneralSecurityException {
                    if (wantKeyId && !keyName.equals(arg0)) {
                        throw new GeneralSecurityException("No id");
                    }
                    if (!algorithm.equals(arg1)) {
                        throw new GeneralSecurityException("Bad algorithm");
                    }
                    return key;
                }
            }));
        }
        optionalUpdate(baseSignatures + prefix("a" + keyBits) + 
                getAlgorithm(algorithm) + '@' + keyIndicator(wantKeyId, false), signedData, false);
    }

    static byte[] getDataToSign() throws Exception {
        return new CBORTextStringMap()
            .setObject("instant", new CBORDateTime("2021-06-10T11:23:06Z"))
            .setObject("name", new CBORTextString("John Doe"))
            .setObject("id", new CBORInteger(123456))
            .encode();
    }
    
    static CBORTextStringMap parseDataToSign() throws Exception {
        return CBORObject.decode(getDataToSign()).getTextStringMap();
    }

    static byte[] createSignature(CBORSigner signer) throws Exception {
        return parseDataToSign().sign(SIGNATURE_LABEL, signer).encode();
    }
    
    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JSF or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }
    
    
    static String keyIndicator(boolean wantKeyId, boolean wantPublicKey) {
        return (wantKeyId ? (wantPublicKey ? "pub+kid" : "kid") : wantPublicKey ? "pub" : "imp") + ".cbor";
    }
    
    static String getAlgorithm(SignatureAlgorithms algorithm) throws IOException {
        return algorithm.getJoseAlgorithmId().toLowerCase();
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
        CBORAsymSignatureValidator validator = new CBORAsymSignatureValidator(keyPair.getPublic());
        CBORTextStringMap decoded = CBORObject.decode(signedData).getTextStringMap();
        decoded.validate(SIGNATURE_LABEL, validator);
        String fileName = baseSignatures + prefix(keyType) +
                getAlgorithm(algorithm) + '@' +  
                keyIndicator(wantKeyId, wantPublicKey);
        decoded.validate(SIGNATURE_LABEL, new CBORAsymSignatureValidator(
                new CBORAsymSignatureValidator.KeyLocator() {
            
            @Override
            public PublicKey locate(PublicKey arg0, String arg1, AsymSignatureAlgorithms arg2)
                    throws IOException, GeneralSecurityException {
                if (wantPublicKey && !keyPair.getPublic().equals(arg0)) {
                    throw new GeneralSecurityException("Missing public key");
                }
                if (wantKeyId && !keyId.equals(arg1)) {
                    throw new GeneralSecurityException("Missing key Id");
                }
                if (algorithm != arg2) {
                    throw new GeneralSecurityException("Missing algorithm");
                }
                return keyPair.getPublic();
            }
        }));
        optionalUpdate(fileName, signedData, 
                algorithm.getMGF1ParameterSpec() != null ||
                algorithm.getKeyType() == KeyTypes.EC);
    }
}
/*
 *  Copyright 2006-2018 WebPKI.org (http://webpki.org).
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

import java.security.KeyPair;
import java.security.KeyStore;

import java.security.cert.X509Certificate;

import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONArrayWriter;
import org.webpki.json.JSONAsymKeySigner;
import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONSigner;
import org.webpki.json.JSONSymKeySigner;
import org.webpki.json.JSONSymKeyVerifier;
import org.webpki.json.JSONX509Signer;
import org.webpki.json.JSONX509Verifier;
// Test
import org.webpki.json.Extension1;
import org.webpki.json.Extension2;
import org.webpki.json.SymmetricKeys;

import org.webpki.util.ArrayUtil;
import org.webpki.util.PEMDecoder;

/*
 * Create JSF test vectors
 */
public class Signatures {
    static String baseKey;
    static String baseData;
    static String baseSignatures;
    static SymmetricKeys symmetricKeys;
    static JSONX509Verifier x509Verifier;
    static String keyId;
    
    static final String[] UNSIGNED_DATA = new String[]{"myUnsignedData"};
    
    static JSONObjectWriter getMixedData() throws IOException {
        return new JSONObjectWriter()
            .setString("mySignedData", "something")
            .setString("myUnsignedData", "something else");
    }

    static void setExtensionData(JSONSigner signer, boolean first) throws IOException {
        if (first) {
            signer.setExtensionNames(new String[]{new Extension1().getExtensionUri(),
                                                  new Extension2().getExtensionUri()});
        }
        signer.setExtensionData(new JSONObjectWriter()
            .setString(new Extension1().getExtensionUri(), first ?
                        "Cool Stuff" : "Other Data")
            .setDynamic((wr) -> {
                return first ? wr.setObject(new Extension2().getExtensionUri(), 
                                           new JSONObjectWriter().setBoolean("life-is-great", true)) : wr;
            }));
    }

    public static void main(String[] args) throws Exception {
        if (args.length != 3) {
            throw new Exception("Wrong number of arguments");
        }
        CustomCryptoProvider.forcedLoad(true);
        baseKey = args[0] + File.separator;
        baseData = args[1] + File.separator;
        baseSignatures = args[2] + File.separator;
        symmetricKeys = new SymmetricKeys(baseKey);
        
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setCertificateEntry("mykey",
            CertificateUtil.getCertificateFromBlob(ArrayUtil.readFile(baseKey + "rootca.cer")));
        x509Verifier = new JSONX509Verifier(new KeyStoreVerifier(keyStore));

        for (String key : new String[]{"p256", "p384", "p521", "r2048"}) {
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
            // Now to the real stuff
            asymSignOptionalPublicKeyInfo(key, true,  false);
            asymSignOptionalPublicKeyInfo(key, false, false);
            asymSignOptionalPublicKeyInfo(key, false, true);
            certSign(key);
            asymJavaScriptSignature(key);
        }
      
        for (int i = 0; i < 2; i++) {
            symmSign(256, MACAlgorithms.HMAC_SHA256, i == 0);
            symmSign(384, MACAlgorithms.HMAC_SHA384, i == 0);
            symmSign(512, MACAlgorithms.HMAC_SHA512, i == 0);
        }
        
        multipleSign("p256", "r2048",  false, false, false, null);
        multipleSign("p256", "p384",   false, false, false, null);
        multipleSign("p256", "p256-2", false, false, false, AsymSignatureAlgorithms.ECDSA_SHA256);
        multipleSign("p256", "p256-2", false, false, true,  AsymSignatureAlgorithms.ECDSA_SHA256);
        multipleSign("p256", "p384",   false, true,  false, null);
        multipleSign("p256", "r2048",  false, true,  true,  null);
        multipleSign("p256", "r2048",  false, false, true,  null);
        multipleSign("p256", "r2048",  true,  false, true,  null);
        multipleSign("p256", "p384",   true,  false, false, null);
        multipleSign("p256", "p384",   true,  true,  false, null);

        asymSignCore("p256", false, true,  true,  false); 
        asymSignCore("p256", false, true,  false, true);
        asymSignCore("p256", true,  false, false, true);
        
        arraySign("p256", false);
        arraySign("r2048", true);
    }

    static void arraySign(String keyType, boolean exts) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        JSONSigner signer = 
                new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null);
        signer.setOutputPublicKeyInfo(true);
        if (exts) {
            setExtensionData(signer, true);
        }
        byte[] signedData = new JSONArrayWriter()
            .setInt(90000)
            .setObject(new JSONObjectWriter()
                .setBoolean("success-is-inevitable", true)
                .setDouble("pi-approximation", 3.14159265359))
            .setString("The quick brown fox...")
            .setSignature(signer).serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        JSONCryptoHelper.ExtensionHolder extensionHolder = new JSONCryptoHelper.ExtensionHolder()
            .addExtension(Extension1.class, false)
            .addExtension(Extension2.class, false);
        if (exts) {
            options.setPermittedExtensions(extensionHolder);
        }
        JSONSignatureDecoder decoder = JSONParser.parse(signedData)
            .getJSONArrayReader().getSignature(options);
        String fileName = baseSignatures + prefix(keyType) + getAlgorithm(decoder) + "@arr-" +
            (exts ? "exts-" : "") + "jwk.json";
        boolean changed = true;
        try {
            if (cleanArraySignature(signedData).equals(cleanArraySignature(ArrayUtil.readFile(fileName)))) {
                return;
            }
        } catch (Exception e) {
            changed = false;  // New
        }
        ArrayUtil.writeFile(fileName, signedData);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
     }

    static String cleanArraySignature(byte[] signedData) throws IOException {
        JSONArrayReader array = JSONParser.parse(signedData).getJSONArrayReader();
        for (int q = 1; q < array.size(); q++) {
            array.scanAway();
        }
        array.getObject().removeProperty(JSONCryptoHelper.VALUE_JSON);
        return new JSONArrayWriter(array).toString();
    }

    static String cleanJavaScriptSignature(byte[] signature) throws IOException {
        String text = new String(signature, "utf-8");
        int i = text.indexOf(" " + JSONCryptoHelper.VALUE_JSON + ": \"");
        int j = text.indexOf('"', i + JSONCryptoHelper.VALUE_JSON.length() + 4);
        return text.substring(0, i) + text.substring(j);
    }

    static void asymJavaScriptSignature(String keyType) throws Exception {
        KeyPair localKey = readJwk(keyType);
        JSONObjectWriter javaScriptSignature = new JSONObjectWriter()
            .setString("statement", "Hello Signed World!")
            .setArray("otherProperties", 
                      new JSONArrayWriter()
                .setInt(2000)
                .setBoolean(true));
        javaScriptSignature.setSignature(new JSONAsymKeySigner(localKey.getPrivate(), localKey.getPublic(), null));
        JSONSignatureDecoder decoder = new JSONObjectReader(javaScriptSignature)
            .getSignature(new JSONCryptoHelper.Options());
        byte[] signatureData = javaScriptSignature.serializeToBytes(JSONOutputFormats.PRETTY_JS_NATIVE);
        String fileName = baseSignatures + prefix(keyType) + getAlgorithm(decoder) + "@jwk.js";
        boolean changed = true;
        try {
            if (cleanJavaScriptSignature(signatureData).equals(cleanJavaScriptSignature(ArrayUtil.readFile(fileName)))) {
                return;
            }
        } catch (Exception e) {
            changed = false;  // New
        }
        ArrayUtil.writeFile(fileName, signatureData);
        if (changed) {
            System.out.println("WARNING '" + fileName + "' was UPDATED");
        }
    }

    static String prefix(String keyType) {
        return keyType + '#';
    }
    
    static String cleanSignature(byte[] signedData) throws IOException {
        JSONObjectReader reader = JSONParser.parse(signedData);
        JSONObjectReader signature = reader.getObject(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON);
        if (signature.hasProperty(JSONCryptoHelper.SIGNERS_JSON)) {
            JSONArrayReader array = signature.getArray(JSONCryptoHelper.SIGNERS_JSON);
            while (array.hasMore()) {
                array.getObject().removeProperty(JSONCryptoHelper.VALUE_JSON);
            }
        } else {
            signature.removeProperty(JSONCryptoHelper.VALUE_JSON);
        }
        return reader.toString();
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

    static void symmSign(int keyBits, MACAlgorithms algorithm, boolean wantKeyId) throws Exception {
        byte[] key = symmetricKeys.getValue(keyBits);
        String keyName = symmetricKeys.getName(keyBits);
        JSONSymKeySigner signer = new JSONSymKeySigner(key, algorithm);
        if (wantKeyId) {
            signer.setKeyId(keyName);
        }
        byte[] signedData = createSignature(signer);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        options.setRequirePublicKeyInfo(false);
        if (wantKeyId) {
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        JSONSignatureDecoder decoder = 
                JSONParser.parse(signedData).getSignature(options);
        decoder.verify(new JSONSymKeyVerifier(key));
        optionalUpdate(baseSignatures + prefix("a" + keyBits) + 
                getAlgorithm(decoder) + '@' + keyIndicator(wantKeyId, false), signedData, false);
    }

    static String getDataToSign() throws Exception {
        return new String(ArrayUtil.readFile(baseData +
                                             "datatobesigned.json"), 
                          "UTF-8").replace("\r", "");
    }
    
    static JSONObjectWriter parseDataToSign() throws Exception {
        return new JSONObjectWriter(JSONParser.parse(getDataToSign()));
    }

    static byte[] createSignature(JSONSigner signer) throws Exception {
        String signed = parseDataToSign().setSignature(signer).toString();
        int i = signed.indexOf(",\n  \"" + JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "\":");
        String unsigned = getDataToSign();
        int j = unsigned.lastIndexOf("\n}");
        return (unsigned.substring(0,j) + signed.substring(i)).getBytes("UTF-8");
    }
    
    static byte[] createSignatures(Vector<JSONSigner> signers,
                                   boolean excl) throws Exception {
        JSONObjectWriter dataToSign = excl ? getMixedData() : parseDataToSign();
        for (JSONSigner signer : signers) {
            dataToSign.setMultiSignature(signer);
        }
        if (excl) {
            return dataToSign.serializeToBytes(JSONOutputFormats.PRETTY_PRINT);
        }
        String signed = dataToSign.toString();
        int i = signed.indexOf(",\n  \"" + JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "\":");
        String unsigned = getDataToSign();
        int j = unsigned.lastIndexOf("\n}");
        return (unsigned.substring(0,j) + signed.substring(i)).getBytes("UTF-8");
    }

    static KeyPair readJwk(String keyType) throws Exception {
        JSONObjectReader jwkPlus = JSONParser.parse(ArrayUtil.readFile(baseKey + keyType + "privatekey.jwk"));
        // Note: The built-in JWK decoder does not accept "kid" since it doesn't have a meaning in JCS or JEF. 
        if ((keyId = jwkPlus.getStringConditional("kid")) != null) {
            jwkPlus.removeProperty("kid");
        }
        return jwkPlus.getKeyPair();
    }
    
    static void multipleSign(String keyType1, String keyType2, 
                             boolean exts, boolean excl, boolean wantKeyId, 
                             AsymSignatureAlgorithms globalAlgorithm) throws Exception {
        KeyPair keyPair1 = readJwk(keyType1);
        String keyId1 = keyId;
        KeyPair keyPair2 = readJwk(keyType2);
        String keyId2 = keyId;
        Vector<JSONSigner> signers = new Vector<JSONSigner>();
        JSONAsymKeySigner signer = new JSONAsymKeySigner(keyPair1.getPrivate(), keyPair1.getPublic(), null);
        if (exts) {
            setExtensionData(signer, true);
        }
        if (wantKeyId) {
            signer.setKeyId(keyId1);
            signer.setOutputPublicKeyInfo(false);
        }
        if (excl) {
            signer.setExcluded(UNSIGNED_DATA);
        }
        signers.add(signer);
        signer = new JSONAsymKeySigner(keyPair2.getPrivate(), keyPair2.getPublic(), null); 
        if (exts) {
            setExtensionData(signer, false);
        }
        if (wantKeyId) {
            signer.setKeyId(keyId2);
            signer.setOutputPublicKeyInfo(false);
        }
        signers.add(signer);
        JSONCryptoHelper.ExtensionHolder extensionHolder = new JSONCryptoHelper.ExtensionHolder()
            .addExtension(Extension1.class, false)
            .addExtension(Extension2.class, false);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        String fileExt = "";
        if (excl) {
            options.setPermittedExclusions(UNSIGNED_DATA);
            fileExt += "-excl";
        }
        if (exts) {
            fileExt += "-exts";
            options.setPermittedExtensions(extensionHolder);
        }
        if (wantKeyId) {
            options.setRequirePublicKeyInfo(false);
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
        }
        byte[] signedData = createSignatures(signers, excl);
        Vector<JSONSignatureDecoder> signatures = JSONParser.parse(signedData).getMultiSignature(options);
        signatures.get(0).verify(new JSONAsymKeyVerifier(keyPair1.getPublic()));
        signatures.get(1).verify(new JSONAsymKeyVerifier(keyPair2.getPublic()));
        if (signatures.size() != 2) {
            throw new Exception("Wrong multi");
        }
        optionalUpdate(baseSignatures + prefix(keyType1) + getAlgorithm(signatures.get(0)) + ","
                                      + prefix(keyType2) + getAlgorithm(signatures.get(1))
                                      + "@mult" + fileExt + (wantKeyId ? "-kid.json" : "-jwk.json"),
                       signedData,
                       true);
     }
    
    static String keyIndicator(boolean wantKeyId, boolean wantPublicKey) {
        return (wantKeyId ? (wantPublicKey ? "jwk+kid" : "kid") : wantPublicKey ? "jwk" : "imp") + ".json";
    }
    
    static String getAlgorithm(JSONSignatureDecoder decoder) throws IOException {
        return decoder.getAlgorithm().getAlgorithmId(AlgorithmPreferences.JOSE).toLowerCase();
    }

    static JSONSignatureDecoder asymSignCore(String keyType, 
                                             boolean wantKeyId,
                                             boolean wantPublicKey,
                                             boolean wantExtensions,
                                             boolean wantExclusions) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        JSONSigner signer = 
                new JSONAsymKeySigner(keyPair.getPrivate(), keyPair.getPublic(), null);
        if (wantKeyId) {
            signer.setKeyId(keyId);
        }
        signer.setOutputPublicKeyInfo(wantPublicKey);
        if (wantExtensions) {
            setExtensionData(signer, true);
        }
        byte[] signedData;
        if (wantExclusions) {
            signer.setExcluded(UNSIGNED_DATA);
            JSONObjectWriter mixedData = getMixedData().setSignature(signer);
            signedData = mixedData.serializeToBytes(JSONOutputFormats.PRETTY_PRINT);

        } else {
            signedData = createSignature(signer);
        }
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        options.setRequirePublicKeyInfo(wantPublicKey);
        options.setKeyIdOption(wantKeyId ? 
                 JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED : JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN);
        if (wantExtensions) {
            JSONCryptoHelper.ExtensionHolder eh = new JSONCryptoHelper.ExtensionHolder();
            eh.addExtension(Extension1.class, true);
            eh.addExtension(Extension2.class, true);
            options.setPermittedExtensions(eh);
        }
        if (wantExclusions) {
            options.setPermittedExclusions(UNSIGNED_DATA);
        }
        String addedFeature = wantExtensions ? "exts-" : (wantExclusions ? "excl-" : "");
        JSONSignatureDecoder decoder = 
            JSONParser.parse(signedData).getSignature(options);
        optionalUpdate(baseSignatures + prefix(keyType) + getAlgorithm(decoder) + '@' +  
                addedFeature + keyIndicator(wantKeyId, wantPublicKey), signedData, true);
        return decoder;
     }

    static JSONSignatureDecoder asymSignOptionalPublicKeyInfo(String keyType, boolean wantKeyId, boolean wantPublicKey) throws Exception {
        return asymSignCore(keyType, wantKeyId, wantPublicKey, false, false);
    }

    static X509Certificate[] readCertificatePath(String keyType) throws IOException {
        return PEMDecoder.getCertificatePath(ArrayUtil.readFile(baseKey + keyType + "certpath.pem"));
    }

    static void certSign(String keyType) throws Exception {
        KeyPair keyPair = readJwk(keyType);
        byte[] signedData = createSignature(new JSONX509Signer(keyPair.getPrivate(), 
                                                               readCertificatePath(keyType),
                                                               null));
        JSONSignatureDecoder decoder = 
                JSONParser.parse(signedData).getSignature(new JSONCryptoHelper.Options());
        decoder.verify(x509Verifier);
        optionalUpdate(baseSignatures + prefix(keyType) + getAlgorithm(decoder) + "@cer.json", signedData, true);
    }
}
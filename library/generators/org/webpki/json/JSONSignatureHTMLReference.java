/*
 *  Copyright 2006-2020 WebPKI.org (http://webpki.org).
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

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyStore;

import java.security.cert.X509Certificate;

import java.util.ArrayList;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.KeyStoreVerifier;
import org.webpki.crypto.MACAlgorithms;

import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;
import org.webpki.util.PEMDecoder;

/**
 * Create an HTML description of the JSON Signature Format (JSF).
 * 
 * @author Anders Rundgren
 */
public class JSONSignatureHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;
    
    static final String ECMASCRIPT_MODE         = "ECMAScript Mode";

    static final String TEST_VECTORS            = "Test Vectors";
    
    static final String MULTIPLE_SIGNATURES     = "Multiple Signatures";
    
    static final String SIGNATURE_CHAINS        = "Signature Chains";
    
    static final String COUNTER_SIGNATURES      = "Counter Signatures";
    
    static final String SAMPLE_OBJECT           = "Sample Object";

    static final String SECURITY_CONSIDERATIONS = "Security Considerations";
    
    static final String ECMASCRIPT_CONSTRAINT   = "ECMAScript Constraint";
    
    static final String GLOBAL_SIGNATURE_OPTIONS = "Global Signature Options";
    static final String SIGNATURE_CORE_OBJECT    = "signaturecore";
    static final String MULTI_SIGNATURE_OBJECT   = "multisignature";
    static final String SIGNATURE_CHAIN_OBJECT   = "signaturechain";
    
    static final String FILE_SAMPLE_SIGN         = "p256#es256@jwk.json";
    static final String FILE_CHAIN_SIGN          = "p256#es256,r2048#rs256@chai-jwk.json";
    static final String FILE_CHAIN_EXTS_SIGN     = "p256#es256,r2048#rs256@chai-exts-kid.json";
    static final String FILE_MULT_SIGN           = "p256#es256,r2048#rs256@mult-jwk.json";
    static final String FILE_MULT_EXTS_SIGN      = "p256#es256,r2048#rs256@mult-exts-kid.json";
    static final String FILE_MULT_EXCL_SIGN      = "p256#es256,r2048#rs256@mult-excl-kid.json";
    static final String FILE_EXTS_SIGN           = "p256#es256@exts-jwk.json";
    static final String FILE_EXCL_SIGN           = "p256#es256@excl-jwk.json";
    static final String FILE_NAME_SIGN           = "p256#es256@name-jwk.json";
 
    static JSONObjectReader readJSON(String name) throws IOException {
        return JSONParser.parse(ArrayUtil.getByteArrayFromInputStream(JSONEncryptionHTMLReference.class.getResourceAsStream(name)));
    }
    
    static String formatCode(String code) {
        StringBuilder s = new StringBuilder("<div style=\"padding:10pt 0pt 10pt 20pt;word-break:break-all\"><code>");
        int lc = 0;
        for (char c : code.toCharArray()) {
            if (c == '\n') {
                lc = 0;
                s.append("<br>");
                continue;
            }
            if (lc == 109) {
                lc = 0;
                s.append("<br>");
            }
            if (c == ' ') {
                s.append("&nbsp;");
            } else if (c == '\"') {
                s.append("&quot;");
            } else {
                s.append(c);
            }
            lc++;
        }
        return s.append("</code></div>").toString();
    }
    
    static String formatCode(JSONObjectReader rd) {
        return formatCode(rd.toString());
    }

    static String formatCode(AsymKey asymKey) {
        return formatCode(asymKey.text);
    }
    
    static ArrayList<AsymKey> asymmetricKeys = new ArrayList<>();

    static ArrayList<SymKey> symmetricKeys = new ArrayList<>();

    static class CoreKey {
        String keyId;
        String fileName;
        String text;
    }
    
    static class AsymKey extends CoreKey {
        KeyPair keyPair;
        X509Certificate[] certPath;
    }
    
    static class SymKey extends CoreKey {
        byte[] keyValue;
    }
    
    static AsymKey readAsymKey(String keyType) throws IOException {
        AsymKey asymKey = new AsymKey();
        JSONObjectReader key = json.readJson1(asymKey.fileName = keyType + "privatekey.jwk");
        asymKey.text = key.toString();
        asymKey.keyId = key.getString("kid");
        key.removeProperty("kid");
        asymKey.keyPair = key.getKeyPair();
        asymKey.certPath = PEMDecoder.getCertificatePath(json.readFile1(keyType + "certpath.pem"));
        return asymKey;
    }

    static SymKey readSymKey(String keyName) throws IOException {
        SymKey symKey = new SymKey();
        symKey.text = new String(json.readFile1(symKey.fileName = keyName + ".hex"), "utf-8");
        symKey.keyValue = DebugFormatter.getByteArrayFromHex(symKey.text);
        symKey.keyId = keyName;
        return symKey;
    }
    
    static String readSignature(String name) throws IOException {
        return new String(json.readFile2(name), "UTF-8");
    }
    
    static JSONX509Verifier certroot;

    static void updateNormalization(StringBuilder normalizedSampleSignature,
                                    String property,
                                    JSONObjectReader sampleSignatureDecoded) throws IOException {
        int i = normalizedSampleSignature.indexOf("\u0000");
        normalizedSampleSignature.deleteCharAt(i);
        normalizedSampleSignature.insert(i, sampleSignatureDecoded.getString(property));
    }

    static String pemFile(String name) throws IOException {
        String pem = new String(json.readFile1(name), "UTF-8");
        return pem.substring(0, pem.length() - 1);
    }
    
    static String readSymSignature(String[] encObjects) throws IOException, GeneralSecurityException {
        StringBuilder s = new StringBuilder();
        for (String name : encObjects) {
            String signature = readSignature(name);
            JSONSignatureDecoder dec = JSONParser.parse(signature).getSignature(
                    new JSONCryptoHelper.Options()
                        .setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED)
                        .setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN));
            for (SymKey symKey : symmetricKeys) {
                byte[] key = symKey.keyValue;
                if (key.length == dec.getSignatureValue().length) {
                    s.append(LINE_SEPARATOR + "HMAC key named <code>&quot;")
                     .append(symKey.keyId)
                     .append("&quot;</code> here provided in hexadecimal notation:")
                     .append(formatCode(symKey.text))
                     .append(showTextAndCode("The following object was signed by the key above:",
                                             name, 
                                             signature));
                    dec.verify(new JSONSymKeyVerifier(key));
                    if (!symKey.keyId.equals(dec.getKeyId())) {
                        throw new IOException("Sym sign");
                    }
                    signature = null;
                    break;
                }
            }
            if (signature != null) {
                throw new IOException("No key for:\n" + signature);
            }
        }
        return s.toString();
    }

    static void scanObject(JSONObjectReader coreSignature, JSONCryptoHelper.Options options) throws IOException {
        if (coreSignature.hasProperty(JSONCryptoHelper.KEY_ID_JSON) && 
            options.keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN) {
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.OPTIONAL);
        }
        if (coreSignature.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH_JSON)) {
            options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.CERTIFICATE_PATH);
        } else if (!coreSignature.hasProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)) {
            options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.OPTIONAL);
        }
    }
    
    static String validateAsymSignature (String fileName) throws IOException {
        System.out.println(fileName);
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        JSONObjectReader signedObject = json.readJson2(fileName);
        try {
            JSONObjectReader checker = signedObject.clone();
            String signatureLabel = JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON;
            if (!checker.hasProperty(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON)) {
                signatureLabel = "authorizationSignature";
            }
            checker = checker.getObject(signatureLabel);
            if (checker.hasProperty(JSONCryptoHelper.EXTENSIONS_JSON)) {
                options.setPermittedExtensions(new JSONCryptoHelper.ExtensionHolder()
                    .addExtension(Extension1.class, false)
                    .addExtension(Extension2.class, false));
            }
            if (checker.hasProperty(JSONCryptoHelper.EXCLUDES_JSON)) {
                options.setPermittedExclusions(checker.getStringArray(JSONCryptoHelper.EXCLUDES_JSON));
            }
            ArrayList<JSONSignatureDecoder> signers = new ArrayList<>();
            if (checker.hasProperty(JSONCryptoHelper.SIGNERS_JSON)) {
                JSONArrayReader signerArray = checker.getArray(JSONCryptoHelper.SIGNERS_JSON);
                do {
                    scanObject(signerArray.getObject(), options);
                } while (signerArray.hasMore());
                signers = signedObject.getMultiSignature(signatureLabel, options);
            } else if (checker.hasProperty(JSONCryptoHelper.CHAIN_JSON)) {
                JSONArrayReader signerArray = checker.getArray(JSONCryptoHelper.CHAIN_JSON);
                do {
                    scanObject(signerArray.getObject(), options);
                } while (signerArray.hasMore());
                signers = signedObject.getSignatureChain(signatureLabel, options);
            } else {
                scanObject(checker, options);
                signers.add(signedObject.getSignature(signatureLabel, options));
            }
          done:
            for (JSONSignatureDecoder decoder : signers) {
                String keyId = decoder.getKeyId();
                if (decoder.getSignatureType() == JSONSignatureTypes.X509_CERTIFICATE) {
                    decoder.verify(certroot);
                    continue done;
                } else if (keyId != null) {
                    for (AsymKey localKey : asymmetricKeys) {
                        if (keyId.equals(localKey.keyId)) {
                            decoder.verify(new JSONAsymKeyVerifier(localKey.keyPair.getPublic()));;
                            continue done;
                        }
                    }
                } else if (decoder.getPublicKey() == null) {
                     for (AsymKey localKey : asymmetricKeys) {
                        if (((AsymSignatureAlgorithms)decoder.getAlgorithm()) == 
                                KeyAlgorithms.getKeyAlgorithm(localKey.keyPair.getPublic()).getRecommendedSignatureAlgorithm()) {
                            decoder.verify(new JSONAsymKeyVerifier(localKey.keyPair.getPublic()));;
                            continue done;
                        }
                    }
                } else {
                    continue done;
                }
                throw new IOException("No key!");
            }
        } catch (Exception e) {
            throw new IOException("Failed on file " + fileName + ", " + e.getMessage());
        }
        return signedObject.toString();
    }

    static String showTextAndCode(String text, String fileName, String code) throws IOException {
        String link = JSONBaseHTML.makeLink(fileName);
        return "<div style=\"cursor:pointer;font-weight:bold;padding:10pt 0 7pt 0\" onclick=\"document.location.href='#" +
               link + "'\" id=\"" + link + 
               "\">" + fileName + "</div>" +
               text + 
               formatCode(code);
    }

    static String showAsymSignature(String text, String signatureFile) throws IOException {
        return showTextAndCode(text, signatureFile, validateAsymSignature(signatureFile));
    }

    static String showKey(String text, CoreKey key) throws IOException {
        return showTextAndCode(text, key.fileName, key.text);
    }
    
    static String keyLink(CoreKey key) throws IOException {
        return JSONBaseHTML.globalLinkRef(key.fileName);
    }
    
    static String coreSignatureDescription(AsymKey key) throws IOException {
        return "The following object was signed by the " +
                keyLink(key) +
                " key";
    }

    static String implicitKeySignature(AsymKey key) throws IOException {
        return coreSignatureDescription(key) +
                " while the public key is supposed to be <i>implicitly</i> known by the verifier:";
    }
    
    static String explicitKeySignature(AsymKey key) throws IOException {
        return coreSignatureDescription(key) + ":";
    }

    static String certificateSignature(AsymKey key) throws IOException {
        return coreSignatureDescription(key) +
                " while the public key is featured in a " +
                JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT, JSONCryptoHelper.CERTIFICATE_PATH_JSON) + ":";
    }

    static String KEY_ID_REFERENCE;
    
    static {
        try {
            KEY_ID_REFERENCE = JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT, JSONCryptoHelper.KEY_ID_JSON);
        } catch (IOException e) {
        }
    }

    static String EXTENSION_REFERENCE;
    
    static {
        try {
            EXTENSION_REFERENCE = ". There is also an " +
                    JSONBaseHTML.globalLinkRef(GLOBAL_SIGNATURE_OPTIONS, JSONCryptoHelper.EXTENSIONS_JSON) +
                    " list";
        } catch (IOException e) {
        }
    }

    static String EXCLUDES_REFERENCE;
    
    static {
        try {
            EXCLUDES_REFERENCE = ". There is also an " +
                    JSONBaseHTML.globalLinkRef(GLOBAL_SIGNATURE_OPTIONS, JSONCryptoHelper.EXCLUDES_JSON) +
                    " list";
        } catch (IOException e) {
        }
    }

    static String keyIdSignature(AsymKey key) throws IOException {
        return coreSignatureDescription(key) +
                " while the public key is identified by a " + KEY_ID_REFERENCE + " property:";
    }
    
    static String multiSignatureText(AsymKey key1, AsymKey key2, String options) throws IOException {
        return "The following object was signed by multiple signatures (see " +
                JSONBaseHTML.globalLinkRef(MULTIPLE_SIGNATURES) +
                ") using the " + keyLink(key1) +
                " and " +  keyLink(key2) + " keys" + options + ":";
    }

    static String signatureChainText(AsymKey key1, AsymKey key2, String options) throws IOException {
        return "The following object was signed by a chain of signatures (see " +
                JSONBaseHTML.globalLinkRef(SIGNATURE_CHAINS) +
                ") using the " + keyLink(key1) +
                " and " +  keyLink(key2) + " keys" + options + ":";
    }

    static String jwsCounterPart(String keyword) {
        return ("JWS counterpart: <code>&quot;" + keyword + "&quot;</code>.");
    }
    public static void main (String args[]) throws Exception {
        json = new JSONBaseHTML(args, "JSF - JSON Signature Format");
        
        json.setFavIcon("../webpkiorg.png");

        AsymKey p256key = readAsymKey("p256");
        AsymKey p384key = readAsymKey("p384");
        AsymKey p521key = readAsymKey("p521");
        AsymKey r2048key = readAsymKey("r2048");
        asymmetricKeys.add(p256key);
        asymmetricKeys.add(p384key);
        asymmetricKeys.add(p521key);
        asymmetricKeys.add(r2048key);
        
        symmetricKeys.add(readSymKey("a128bitkey"));
        symmetricKeys.add(readSymKey("a256bitkey"));
        symmetricKeys.add(readSymKey("a384bitkey"));
        symmetricKeys.add(readSymKey("a512bitkey"));

        KeyStore keyStore = KeyStore.getInstance("JKS");
        keyStore.load (null, null);
        keyStore.setCertificateEntry ("mykey",
                                      CertificateUtil.getCertificateFromBlob (json.readFile1("rootca.cer")));        
        certroot = new JSONX509Verifier(new KeyStoreVerifier(keyStore));
        
        json.addParagraphObject().append("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JSF</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Signature Format</span></div>");
        
        json.addTOC();

        json.addParagraphObject("Introduction").append("JSF is a scheme for signing data expressed as JSON ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" objects, loosely modeled after XML&nbsp;DSig's ")
          .append(json.createReference(JSONBaseHTML.REF_XMLDSIG))
          .append(" &quot;enveloped&quot; signatures. " +
          "Note that JSF requires that the JSON data to be signed is compatible with the I-JSON ")
          .append(json.createReference(JSONBaseHTML.REF_IJSON))
          .append(" profile." +
            Types.LINE_SEPARATOR +
             "Unlike JSON Web Signature (JWS) ")
          .append(json.createReference(JSONBaseHTML.REF_JWS))
          .append(
            " which was designed for signing <i>any</i> kind of data, " +
            "a JSF signature is intended to be an <i>integral part of a JSON object</i> " +
            "with message centric systems like Yasmin ")
          .append(json.createReference(JSONBaseHTML.REF_YASMIN))
          .append(" as the primary target. " +
            "This concept was not originally considered " +
            "due to the lack of a standardized canonicalization method for JSON data. " +
            "However, with the introduction of the JSON Canonicalization Scheme ")
           .append(json.createReference(JSONBaseHTML.REF_JCS))
           .append(" both data and header information could be provided in plain text while still being " +
           "subject to cryptographic operations." + Types.LINE_SEPARATOR +
            "In order to make library support of JSF straightforward in spite of " +
           "having a different structure compared to JWS, JSF uses the same JWA ")
          .append(json.createReference(JSONBaseHTML.REF_JWA))
          .append(" cryptographic algorithms." + Types.LINE_SEPARATOR +
            "JSF may also be used for &quot;in-object&quot; JavaScript signatures, " +
            "making JSF suitable for HTML5 applications. See " +
            "<a href=\"#" + JSONBaseHTML.makeLink(ECMASCRIPT_MODE) + 
            "\"><span style=\"white-space:nowrap\">" +
            ECMASCRIPT_MODE + "</span></a>." + Types.LINE_SEPARATOR +
            "There is also a &quot;companion&quot; specification for encryption coined JEF ")
          .append(json.createReference(JSONBaseHTML.REF_JEF))
          .append(".");

        String sampleSignature = formatCode(validateAsymSignature(FILE_SAMPLE_SIGN));
        int beginValue = sampleSignature.indexOf("},");
        sampleSignature = sampleSignature.substring(0, ++beginValue) +
                "<span style=\"background:#f0f0f0\">,</span>" + 
                sampleSignature.substring(++beginValue);
        beginValue = sampleSignature.indexOf("&quot;" + 
                JSONCryptoHelper.VALUE_JSON + "&quot;");
        sampleSignature = sampleSignature.substring(0, beginValue) + 
                "<span style=\"background:#f0f0f0\">" + 
                sampleSignature.substring(beginValue);
        beginValue = sampleSignature.indexOf("<br>", beginValue);
        sampleSignature = sampleSignature.substring(0, beginValue) + 
                "</span>" + 
                sampleSignature.substring(beginValue);
        
        JSONObjectReader parsedSample = JSONParser.parse(readSignature(FILE_SAMPLE_SIGN));
        parsedSample.getObject(JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON)
            .removeProperty(JSONCryptoHelper.VALUE_JSON);

        json.addParagraphObject(SAMPLE_OBJECT).append(
            "The following <i>cryptographically verifiable</i> sample signature is used to visualize the JSF specification:")
        .append(sampleSignature)
        .append("The sample signature's payload consists of the properties above the <code>&quot;" +
            JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "&quot;</code> property. " +
            "Note: JSF does <i>not</i> mandate any specific ordering of properties like in the sample." + LINE_SEPARATOR +
            "For more examples see " +
            JSONBaseHTML.globalLinkRef(TEST_VECTORS) + 
            "." + LINE_SEPARATOR +
            "The scope of a signature (what is actually signed) comprises all " +
            "properties including possible child objects of the JSON " +
            "object holding the <code>&quot;" + JSONCryptoHelper.VALUE_JSON +
            "&quot;</code> property except for the <code>&quot;" + 
            JSONCryptoHelper.VALUE_JSON + "&quot;</code> property itself (shaded area in the sample).");
        
        json.addDataTypesDescription("JSF consists of an <i>arbitrary but unique top level " +
            "property</i> (see " +
            JSONBaseHTML.globalLinkRef(FILE_NAME_SIGN) +
            ") holding a composite JSON object (" +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
            ", " + 
            JSONBaseHTML.globalLinkRef(MULTI_SIGNATURE_OBJECT) +
            " or " + 
            JSONBaseHTML.globalLinkRef(SIGNATURE_CHAIN_OBJECT) +
            ")." + LINE_SEPARATOR);

        json.addProtocolTableEntry("JSF Objects")
          .append("The following tables describe the JSF JSON structures in detail.");
        
        json.addParagraphObject("Signature Validation").append(
            "JSF implementors are presumed to be familiar with JWS " +
                        json.createReference(JSONBaseHTML.REF_JWS) + "." + LINE_SEPARATOR +
            "Prerequisite: A JSON object in accordance with ")
          .append(json.createReference(JSONBaseHTML.REF_IJSON))
          .append(
            " containing an <i>arbitrary but unique top level " +
            "property</i> (see " +
            JSONBaseHTML.globalLinkRef(FILE_NAME_SIGN) +
            ") holding a JSF " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
            ", " + 
            JSONBaseHTML.globalLinkRef(MULTI_SIGNATURE_OBJECT) +
            " or " + 
            JSONBaseHTML.globalLinkRef(SIGNATURE_CHAIN_OBJECT) +
            " object." + LINE_SEPARATOR +
            "Note that there <b>must not</b> be any not here defined properties inside of the signature object " + 
            " and that the use of JCS " + json.createReference(JSONBaseHTML.REF_JCS) +
            " implies certain constraints on the JSON data." +     
            LINE_SEPARATOR +
            "Since JSF uses the same algorithms as JWS, the JWA " + json.createReference(JSONBaseHTML.REF_JWA) +
            " reference apply. " +
            "The process for recreating the signed data <b>must</b> be performed as follows:<ol>" +
            "<li value=\"1\">The <code>&quot;" + JSONCryptoHelper.VALUE_JSON + "&quot;</code> property " +
            "is <i>deleted</i> from the JSF signature object.</li>" +
            "<li style=\"padding-top:4pt\">The signed data is retrieved by running the " +
            "JCS " + json.createReference(JSONBaseHTML.REF_JCS) +
            " canonicalization method over the remaining object in its entirety.</li>" +
            "</ol>" + 
            "Note that data that is unsigned (as defined by the " +
            JSONBaseHTML.globalLinkRef(GLOBAL_SIGNATURE_OPTIONS, 
            JSONCryptoHelper.EXCLUDES_JSON) + " property), <b>must</b> be excluded " +
            "from the JCS process." +
            LINE_SEPARATOR +
            "Applied on the " +
            JSONBaseHTML.globalLinkRef(SAMPLE_OBJECT) +
            ", a conforming JCS process should return the following JSON string:")
         .append(formatCode(parsedSample.serializeToString(JSONOutputFormats.CANONICALIZED)))
         .append(
            "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
            "The signature supplied in the " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT, JSONCryptoHelper.VALUE_JSON) +
            " property can now be validated by applying the algorithm specified in the " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT, JSONCryptoHelper.ALGORITHM_JSON) + 
            " property (together with the appropriate <i>signature verification key</i>), on the " +
            "<span style=\"white-space:nowrap\">UTF-8</span> representation of the " +
            "canonicalized textual data." + LINE_SEPARATOR +     
            "Path validation (when applicable), is out of scope for JSF, " +
            "but is <i>preferably</i> carried out as described in X.509 " +
            json.createReference(JSONBaseHTML.REF_X509) +
            ".");
        
        json.addParagraphObject("Signature Creation").append(
                "Prerequisite: A JSON object in accordance with ")
        .append(json.createReference(JSONBaseHTML.REF_IJSON))
        .append("." + LINE_SEPARATOR + 
            "The process to sign a JSON object using JSF is as follows:<ol>" +
            "<li value=\"1\">Create a JSF object with all components defined except for the <code>&quot;" + 
            JSONCryptoHelper.VALUE_JSON + "&quot;</code> property.</li>" +
            "<li style=\"padding-top:4pt\">Add the JSF object to the <i>top level</i> JSON object to be " +
            "signed using any valid JSON property name which does not clash with the other <i>top level</i> properties.</li>" +
            "<li style=\"padding-top:4pt\">Generate the required format of the JSON object to be " +
            "signed by running the " +
            "JCS " + json.createReference(JSONBaseHTML.REF_JCS) +
            " canonicalization method over the JSON object in its entirety.</li>" +
            "<li style=\"padding-top:4pt\">Apply the selected signature algorithm and key to the value " +
            "generated in the previous step.</li>" +
            "<li style=\"padding-top:4pt\">Complete the process by adding the " +
            "<code>&quot;" + 
            JSONCryptoHelper.VALUE_JSON + "&quot;</code> property (with the argument set to the result of the previous step), " +
            "to the JSF object.</li>" +
            "</ol>." +
            "Note that data that should not be signed (as defined by the " + 
            JSONBaseHTML.globalLinkRef(GLOBAL_SIGNATURE_OPTIONS, 
            JSONCryptoHelper.EXCLUDES_JSON) + " property), <b>must</b> be excluded " +
            "from the JCS process.");

        json.addParagraphObject(MULTIPLE_SIGNATURES).append("Multiple signatures enable different keys to " +
            "<i>independently of each other</i> add a signature to a JSON object. " + 
            "See the " + "<a href=\"#" + JSONBaseHTML.makeLink(FILE_MULT_SIGN) + "\">Multi Signature Sample</a>." +
            LINE_SEPARATOR +
            "The canonicalization procedure is essentially the same as for simple " +
            "signatures but <b>must</b> also take the following in account:<ul>" +
            "<li>The <code>'['</code> and <code>']'</code> characters <b>must</b> " +
            "be <i>included</i> in the canonicalized data for each " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
            " object.</li>" +
            "<li style=\"padding-top:4pt\">Each signature requires its own canonicalization process. During this " +
            "process the other signature objects <b>must</b> (temporarily) be removed.</li>" +
            "<li style=\"padding-top:4pt\">The <code>','</code> characters separating signature objects <b>must</b> " +
            "be <i>excluded</i> from the canonicalized data.</li>" +
            "</ul>" +
            "See also " + JSONBaseHTML.globalLinkRef(COUNTER_SIGNATURES) + 
            ".");
        
        json.addParagraphObject(SIGNATURE_CHAINS).append("Signature chains require that each added signature " +
            "object does not only sign the data but the preceding signature objects as well. " + 
            "See the " + "<a href=\"#" + JSONBaseHTML.makeLink(FILE_CHAIN_SIGN) + "\">Signature Chain Sample</a>." +
            LINE_SEPARATOR +
            "The canonicalization procedure is essentially the same as for simple " +
            "signatures but <b>must</b> also take the following in account:<ul>" +
            "<li>The <code>'['</code> and <code>']'</code> characters <b>must</b> " +
            "be <i>included</i> in the canonicalized data for each " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
            " object.</li>" +
            "<li style=\"padding-top:4pt\">Each signature requires its own canonicalization process. During signature validation, " +
            "array wise higher order signature objects <b>must</b> (temporarily) be removed " +
            "including leading and trailing <code>','</code> characters.</li>" +
            "<li style=\"padding-top:4pt\">The <code>','</code> characters separating signature objects " +
            "of array wise lower order than the one to add or validate <b>must</b> " +
            "be <i>included</i> in the canonicalized data.</li>" +
             "</ul>" +
            "See also " + JSONBaseHTML.globalLinkRef(COUNTER_SIGNATURES) + 
            ".");

        json.addParagraphObject(SECURITY_CONSIDERATIONS ).append("This specification does (to the author's " +
            "knowledge), not introduce additional vulnerabilities " +
            "over what is specified for JWS " + json.createReference(JSONBaseHTML.REF_JWS) + ".");
        
        json.setAppendixMode();

        json.addParagraphObject(TEST_VECTORS).append(
        "This section holds test data which can be used to verify the correctness of a JSF implementation." +
        showKey(
            "The " + JSONBaseHTML.globalLinkRef(SAMPLE_OBJECT) +
            " was signed by the following EC private key in the JWK " + 
            json.createReference(JSONBaseHTML.REF_JWK) + " format:",
            p256key) + 
        showAsymSignature(
            keyIdSignature(p256key), 
            "p256#es256@kid.json") +
        showAsymSignature(
            implicitKeySignature(p256key), 
            "p256#es256@imp.json") +
        showAsymSignature(
            certificateSignature(p256key),
            "p256#es256@cer.json") +
        showAsymSignature(
            coreSignatureDescription(p256key) +
            " but uses another property name than in the other samples for holding the " + 
            JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
            " object:",
            FILE_NAME_SIGN) +
        showAsymSignature(
            coreSignatureDescription(p256key) +
            EXTENSION_REFERENCE + ":",
            FILE_EXTS_SIGN) +
        showAsymSignature(
            coreSignatureDescription(p256key) +
            EXCLUDES_REFERENCE +
            ":",
            FILE_EXCL_SIGN) +
        showKey("EC private key associated with subsequent objects:", p384key) +
        showAsymSignature(
            explicitKeySignature(p384key),
            "p384#es384@jwk.json") +
        showAsymSignature(
            keyIdSignature(p384key), 
            "p384#es384@kid.json") +
        showAsymSignature(
            implicitKeySignature(p384key), 
            "p384#es384@imp.json") +
        showAsymSignature(
            certificateSignature(p384key),
            "p384#es384@cer.json") +
        showKey("EC private key associated with subsequent objects:", p521key) +
        showAsymSignature(
            explicitKeySignature(p521key),
            "p521#es512@jwk.json") +
        showAsymSignature(
            keyIdSignature(p521key), 
            "p521#es512@kid.json") +
        showAsymSignature(
            implicitKeySignature(p521key), 
            "p521#es512@imp.json") +
        showAsymSignature(
            certificateSignature(p521key),
            "p521#es512@cer.json") +
        showKey("RSA private key associated with subsequent objects:", r2048key) +
        showAsymSignature(
            explicitKeySignature(r2048key),
            "r2048#rs256@jwk.json") +
        showAsymSignature(
            keyIdSignature(r2048key), 
            "r2048#rs256@kid.json") +
        showAsymSignature(
            implicitKeySignature(r2048key), 
            "r2048#rs256@imp.json") +
        showAsymSignature(
            certificateSignature(r2048key),
            "r2048#rs256@cer.json") +
        readSymSignature(new String[]{"a256#hs256@kid.json",
                                      "a384#hs384@kid.json",
                                      "a512#hs512@kid.json"}) +
        showAsymSignature(
            multiSignatureText(p256key, r2048key, ""),
            FILE_MULT_SIGN) +
        showAsymSignature(
            multiSignatureText(p256key, r2048key,
                " while the public keys are identified by " +
                KEY_ID_REFERENCE + " properties" + EXTENSION_REFERENCE +
                ". Note that this JSF features <i>optional</i> extension arguments (the second signature lacks one element)"),
            FILE_MULT_EXTS_SIGN) +
        showAsymSignature(
            multiSignatureText(p256key, r2048key,
                " while the public keys are identified by " +
                KEY_ID_REFERENCE + " properties" + EXCLUDES_REFERENCE),
            FILE_MULT_EXCL_SIGN) +
        showAsymSignature(
            signatureChainText(p256key, r2048key,""),
            FILE_CHAIN_SIGN) +
        showAsymSignature(
            signatureChainText(p256key, r2048key,
            " while the public keys are identified by " +
            KEY_ID_REFERENCE + " properties" + EXTENSION_REFERENCE +
            ". Note that this JSF features <i>optional</i> extension arguments (the second signature lacks one element)"),
            FILE_CHAIN_EXTS_SIGN) +
        showTextAndCode("The certificate based signatures share a common root (here supplied in PEM " +
            json.createReference(JSONBaseHTML.REF_PEM) +
            " format), which can be used for path validation:",
            "rootca.pem",
            pemFile("rootca.pem")).replace(" 10pt ", " 0pt "));

        String jsSignature = formatCode("var signedObject = " +
                                        new String(json.readFile2("p256#es256@jwk.js"), "utf-8") + ";");
        beginValue = jsSignature.indexOf("{");
        jsSignature = jsSignature.substring(0, ++beginValue) +
                      "<br>&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Data&nbsp;to&nbsp;be&nbsp;signed</span>" +
                      jsSignature.substring(beginValue);
        beginValue = jsSignature.indexOf("<br>&nbsp;&nbsp;signature:");
        jsSignature = jsSignature.substring(0, beginValue) +
                      "<br>&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Signature</span>" +
                      jsSignature.substring(beginValue);

        json.addParagraphObject(ECMASCRIPT_MODE).append("ECMAScript mode in this context refers to " +
           "the ability to sign JavaScript objects as well as using the standard JSON support for parsing and " +
           "creating signed data." + LINE_SEPARATOR + 
           "The code snippet below shows a signed JavaScript object:")
        .append(jsSignature)
        .append(
           "Due to the fact that the <code>JSON.stringify()</code> method converts JavaScript objects like above into " +
           "JSON-compliant strings no special considerations are required for JavaScript.");

        json.addParagraphObject(COUNTER_SIGNATURES).append(
            "For counter signatures there are several different solutions where " +
            JSONBaseHTML.globalLinkRef(SIGNATURE_CHAINS) + " is the most straightforward." + LINE_SEPARATOR +
            "Another way dealing with counter signatures is using an " +
            "application level counter signing solution like the following:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&quot;object&quot;: {&quot;type&quot;: &quot;house&quot;, &quot;price&quot;: &quot;$635,000&quot;},<br>" +
            "&nbsp;&nbsp;&quot;role&quot;: &quot;buyer&quot;,<br>" +
            "&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2019-03-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&quot;" + JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "Counter signed JSON object:" +
            "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>{<br>" +
            "&nbsp;&nbsp;&quot;attesting&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;id&quot;: &quot;lADU_sO067Wlgoo52-9L&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;object&quot;: {&quot;type&quot;: &quot;house&quot;, " +
            "&quot;price&quot;: &quot;$635,000&quot;},<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;role&quot;: &quot;buyer&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2019-03-08T13:56:08Z&quot;,<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&quot;" + JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Original signature...</i><code><br>" +
            "&nbsp;&nbsp;&nbsp;&nbsp;}<br>" +
            "&nbsp;&nbsp;},<br>" +
            "&nbsp;&nbsp;&quot;role&quot;: &quot;notary&quot;,<br>" +
            "&nbsp;&nbsp;&quot;timeStamp&quot;: &quot;2016-12-08T13:58:42Z&quot;,<br>" +
            "&nbsp;&nbsp;&quot;" + JSONObjectWriter.SIGNATURE_DEFAULT_LABEL_JSON + "&quot;:&nbsp;{<br>" +
            "&nbsp;&nbsp;&nbsp;<span style=\"font-size:15pt\">&nbsp;</span></code><i>Counter signature...</i><code><br>" +
            "&nbsp;&nbsp;}<br>" +
            "}</code></div>" +
            "For sophisticated <i>peer based</i> counter signature schemes another possibility is using " +
            JSONBaseHTML.globalLinkRef(MULTIPLE_SIGNATURES) + 
            ", <i>optionally</i> including JSF " +
            JSONBaseHTML.globalLinkRef(GLOBAL_SIGNATURE_OPTIONS, JSONCryptoHelper.EXTENSIONS_JSON) +
            " holding application specific (per signature) metadata.");

        json.addParagraphObject("Usage in Applications").append("JSF is a core element in a proof-of-concept application ")
         .append(json.createReference(JSONBaseHTML.REF_WEBPKI_FOR_ANDROID))
         .append(" running on Android." + LINE_SEPARATOR +
         "The sample code below is based on the Java reference implementation ")
         .append(json.createReference(JSONBaseHTML.REF_OPENKEYSTORE))
         .append(" which features an integrated " +
         "JSON encoder, decoder and signature solution:" +
         "<div style=\"padding:10pt 0pt 0pt 20pt\"><code>" +
         "public&nbsp;void&nbsp;signAndVerifyJsf(PrivateKey&nbsp;privateKey,&nbsp;PublicKey&nbsp;publicKey)&nbsp;throws&nbsp;IOException&nbsp;{<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Create&nbsp;an&nbsp;empty&nbsp;JSON&nbsp;document</span><br>" +
         "&nbsp;&nbsp;JSONObjectWriter&nbsp;writer&nbsp;=&nbsp;new&nbsp;JSONObjectWriter();<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Fill&nbsp;it&nbsp;with&nbsp;some&nbsp;data</span><br>" +
         "&nbsp;&nbsp;writer.setString(&quot;myProperty&quot;,&nbsp;&quot;Some&nbsp;data&quot;);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Sign&nbsp;document</span><br>" +
         "&nbsp;&nbsp;writer.setSignature(new&nbsp;JSONAsymKeySigner(privateKey,&nbsp;publicKey,&nbsp;null));<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Serialize&nbsp;document</span><br>" +
         "&nbsp;&nbsp;String&nbsp;json&nbsp;=&nbsp;writer.toString();<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Print&nbsp;document&nbsp;on&nbsp;the&nbsp;console</span><br>" +
         "&nbsp;&nbsp;System.out.println(&quot;Signed&nbsp;doc:\n&quot;&nbsp;+&nbsp;json);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Parse&nbsp;document</span><br>" +
         "&nbsp;&nbsp;JSONObjectReader&nbsp;reader&nbsp;=&nbsp;JSONParser.parse(json);<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Get&nbsp;and&nbsp;verify&nbsp;signature</span><br>" +
         "&nbsp;&nbsp;JSONSignatureDecoder&nbsp;signature&nbsp;=&nbsp;reader.getSignature(new JSONCryptoHelper.Options());<br>" +
         "&nbsp;&nbsp;signature.verify(new&nbsp;JSONAsymKeyVerifier(publicKey));<br>" +
         "<br>" +
         "&nbsp;&nbsp;<span style=\"color:green\">//&nbsp;Print&nbsp;document&nbsp;payload&nbsp;on&nbsp;the&nbsp;console</span><br>" +
         "&nbsp;&nbsp;System.out.println(&quot;Returned&nbsp;data:&nbsp;&quot;&nbsp;+&nbsp;reader.getString(&quot;myProperty&quot;));<br>" +
         "}</code></div>");

        json.addParagraphObject("Acknowledgements").append("During the initial phases of the design process, highly appreciated " +
       "feedback were provided by Manu&nbsp;Sporny, Jim&nbsp;Klo, " +
       "Jeffrey&nbsp;Walton, David&nbsp;Chadwick, Jim&nbsp;Schaad, Mike&nbsp;Jones, David&nbsp;Waite, " +
       "Douglas&nbsp;Crockford, Arne&nbsp;Riiber, Brian&nbsp;Campbell, Sergey&nbsp;Beryozkin, and others."
       + LINE_SEPARATOR +
       "Special thanks go to James&nbsp;Manger who pointed out the ECMAScript ")
       .append(json.createReference(JSONBaseHTML.REF_ES6))
       .append(" number serialization scheme as well as reviewing a related Internet draft." + LINE_SEPARATOR +
        "An early prototype was funded by <i>PrimeKey Solutions AB</i> and the <i>Swedish Innovation Board (VINNOVA)</i>.");
        
        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2013-12-17", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2013-12-20", "0.4", "Changed from Base64 to Base64URL everywhere");
        json.addDocumentHistoryLine("2013-12-29", "0.5", "Added the (now obsoleted) <code>extension</code> facility");
        json.addDocumentHistoryLine("2014-01-21", "0.51", "Added clarification to public key parameter representation");
        json.addDocumentHistoryLine("2014-01-26", "0.52", "Added note regarding the (now obsoleted) <code>signerCertificate</code> option");
        json.addDocumentHistoryLine("2014-04-15", "0.53", "Embedded (the now obsoleted) <code>bigint</code> in JS <i>string</i>");
        json.addDocumentHistoryLine("2014-09-17", "0.54", "Changed (now obsoleted) canonicalization to normalization");
        json.addDocumentHistoryLine("2014-09-23", "0.55", "Aligned EC parameter representation with JWS " + json.createReference(JSONBaseHTML.REF_JWS));
        json.addDocumentHistoryLine("2014-12-08", "0.56", "Removed " + json.createReference(JSONBaseHTML.REF_XMLDSIG) + " bloat and added support for JWA " + json.createReference(JSONBaseHTML.REF_JWS) + " algorithm identifiers");
        json.addDocumentHistoryLine("2014-12-19", "0.57", "Added an interoperability section");
        json.addDocumentHistoryLine("2015-01-12", "0.58", "Added clarification to signature <code>" + JSONCryptoHelper.VALUE_JSON + "</code> representation");
        json.addDocumentHistoryLine("2016-01-11", "0.59", "Added ECMAScript compatibility mode");
        json.addDocumentHistoryLine("2017-04-19", "0.60", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");
        json.addDocumentHistoryLine("2017-05-18", "0.70", "Added multiple signatures and test vectors");
        json.addDocumentHistoryLine("2019-03-05", "0.80", "Rewritten to use the JSON Canonicalization Scheme " + json.createReference(JSONBaseHTML.REF_JCS));
        json.addDocumentHistoryLine("2019-10-12", "0.81", "Added signature chains (<code>" + JSONCryptoHelper.CHAIN_JSON + "</code>)");

        json.addParagraphObject("Author").append("JSF was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore project " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE)  + ".");

        json.addProtocolTable("Top Level Property")
          .newRow()
            .newColumn()
              .addProperty ("...")
              .addLink(SIGNATURE_CORE_OBJECT)
            .newColumn()
              .setType (WEBPKI_DATA_TYPES.OBJECT)
            .newColumn()
              .setChoice (true, 3)
            .newColumn()
              .addString("Unique top level property for <i>simple</i> signatures.")
         .newRow()
           .newColumn()
             .addProperty("...")
             .addLink(MULTI_SIGNATURE_OBJECT)
           .newColumn()
             .setType(WEBPKI_DATA_TYPES.OBJECT)
           .newColumn()
           .newColumn()
             .addString("Unique top level property for ")
             .addLink(MULTIPLE_SIGNATURES)
        .newRow()
        .newColumn()
          .addProperty("...")
          .addLink(SIGNATURE_CHAIN_OBJECT)
        .newColumn()
          .setType(WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Unique top level property for ")
          .addLink(SIGNATURE_CHAINS);
        
        json.addSubItemTable(SIGNATURE_CORE_OBJECT)
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.ALGORITHM_JSON)
              .addSymbolicValue("Algorithm")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
            .newColumn()
              .addString("Signature algorithm. The currently recognized JWA ")
              .addString(json.createReference(JSONBaseHTML.REF_JWA))
              .addString(" asymmetric key algorithms include:")
              .addString(JSONBaseHTML.enumerateJOSEAlgorithms(AsymSignatureAlgorithms.values()))
              .addString("The currently recognized JWA ")
              .addString(json.createReference(JSONBaseHTML.REF_JWA))
              .addString(" symmetric key algorithms include:")
              .addString(JSONBaseHTML.enumerateJOSEAlgorithms(MACAlgorithms.values()))
              .addString("Note: If <i>proprietary</i> signature algorithms are " +
                         "added, they <b>must</b> be expressed as URIs." + Types.LINE_SEPARATOR + 
                         jwsCounterPart("alg"))
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.KEY_ID_JSON)
              .addSymbolicValue("Identifier")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
              .setChoice (false, 1)
            .newColumn()
              .addString("<i>Optional.</i> Application specific string " +
                         "identifying the signature key." + Types.LINE_SEPARATOR + 
                         jwsCounterPart("kid"))
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)
              .addLink (JSONCryptoHelper.PUBLIC_KEY_JSON)
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
            .newColumn()
              .setChoice (false, 2)
            .newColumn()
              .addString("<i>Optional.</i> Public key object." + Types.LINE_SEPARATOR + 
                      jwsCounterPart("jwk"))
          .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.CERTIFICATE_PATH_JSON)
          .addArrayList(Types.CERTIFICATE_PATH, 1)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("<i>Optional.</i> Sorted array of X.509 ")
          .addString(json.createReference(JSONBaseHTML.REF_X509))
          .addString(" certificates, where the <i>first</i> element <b>must</b> " +
                     "contain the <i style=\"white-space:nowrap\">signature certificate</i>. " +
                     "The certificate path <b>must</b> be <i>contiguous</i> " +
                     "but is not required to be complete." + Types.LINE_SEPARATOR + 
                     jwsCounterPart("x5c"))
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.VALUE_JSON)
              .addSymbolicValue("Signature")
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
            .newColumn()
            .newColumn()
              .addString("The signature data." +
              " Note that the <i>binary</i> representation <b>must</b> follow the JWA " + 
                 json.createReference(JSONBaseHTML.REF_JWA) + " specifications.")
              .setNotes ("Note that asymmetric key signatures are <i>not required</i> providing an associated " +
                      JSONBaseHTML.enumerateAttributes(new String[]{JSONCryptoHelper.PUBLIC_KEY_JSON,
                                                   JSONCryptoHelper.CERTIFICATE_PATH_JSON}, false) + 
                   " property since the key may be given by the context or through the <code>&quot;" + 
                   JSONCryptoHelper.KEY_ID_JSON + "&quot;</code> property.");

        json.addSubItemTable(GLOBAL_SIGNATURE_OPTIONS)
          .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.EXTENSIONS_JSON)
              .addArrayList(Types.PROPERTY_LIST, 1)
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
              .setChoice (false, 1)
            .newColumn()
              .addString("<i>Optional.</i> Array holding the names of one or " +
                         "more application specific extension properties " +
              "also featured within the " +
              JSONBaseHTML.globalLinkRef(SIGNATURE_CORE_OBJECT) +
              " signature object." +
              Types.LINE_SEPARATOR +
              "Extension names <b>must not</b> be <i>duplicated</i> or use any " +
              "of the JSF <i>reserved words</i> " +
              JSONBaseHTML.enumerateAttributes(JSONCryptoHelper.jsfReservedWords.toArray(new String[0]), false) + ". " +
              Types.LINE_SEPARATOR +
              "Extensions intended for public consumption are <i>preferably</i> expressed as URIs " +
              "(unless registered with IANA), " +
              "while private schemes are free using any valid property name." + Types.LINE_SEPARATOR +
              "A conforming JSF implementation <b>must</b> support <i>optional</i> extensions values, as well " +
              "as an option to only accept <i>predefined</i> extension property names." +
              Types.LINE_SEPARATOR +
              JSONBaseHTML.referToTestVectors(FILE_EXTS_SIGN, FILE_MULT_EXTS_SIGN) + Types.LINE_SEPARATOR + 
              jwsCounterPart("crit"))
         .newRow()
            .newColumn()
              .addProperty(JSONCryptoHelper.EXCLUDES_JSON)
              .addArrayList(Types.PROPERTY_LIST, 1)
            .newColumn()
              .setType(Types.WEBPKI_DATA_TYPES.STRING)
            .newColumn()
              .setChoice (false, 1)
            .newColumn()
              .addString("<i>Optional.</i> Array holding the names " +
              "of one or more application level properties " +
              "that <b>must</b> be " +
              "<i>excluded</i> from the signature process." +
              Types.LINE_SEPARATOR +
              "Note that the <code>&quot;" + JSONCryptoHelper.EXCLUDES_JSON + 
              "&quot;</code> property itself, <b>must</b> also " +
              "be excluded from the signature process." + 
              Types.LINE_SEPARATOR +
              "Since both the <code>&quot;" + JSONCryptoHelper.EXCLUDES_JSON + 
              "&quot;</code> property and the associated data it points to are <i>unsigned</i>, a conforming " +
              "JSF implementation <b>must</b> provide options for " +
              "specifying which properties to accept." +
              Types.LINE_SEPARATOR +
              JSONBaseHTML.referToTestVectors(FILE_EXCL_SIGN, FILE_MULT_EXCL_SIGN))
              .setNotes("Note that these options <b>must</b> only be specified at the top level of a JSF signature object.");

        json.addSubItemTable(MULTI_SIGNATURE_OBJECT)
        .newRow()
          .newColumn()
            .addProperty (JSONCryptoHelper.SIGNERS_JSON)
            .addArrayLink(SIGNATURE_CORE_OBJECT, 1)
         .newColumn()
           .setType(WEBPKI_DATA_TYPES.OBJECT)
         .newColumn()
         .newColumn()
           .addString("Array holding ")
           .addLink(MULTIPLE_SIGNATURES);
        
        json.addSubItemTable(SIGNATURE_CHAIN_OBJECT)
        .newRow()
          .newColumn()
            .addProperty (JSONCryptoHelper.CHAIN_JSON)
            .addArrayLink(SIGNATURE_CORE_OBJECT, 1)
         .newColumn()
           .setType(WEBPKI_DATA_TYPES.OBJECT)
         .newColumn()
         .newColumn()
           .addString("Array holding ")
           .addLink(SIGNATURE_CHAINS);

        json.AddPublicKeyDefinitions();

        json.writeHTML();
    }

}

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
package org.webpki.json;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.security.interfaces.RSAPublicKey;

import java.util.Vector;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.KeyAlgorithms;

import org.webpki.json.JSONBaseHTML.Extender;
import org.webpki.json.JSONBaseHTML.RowInterface;
import org.webpki.json.JSONBaseHTML.Types;
import org.webpki.json.JSONBaseHTML.ProtocolObject.Row.Column;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

/**
 * Create an HTML description of JEF (JSON Encryption Format).
 * 
 * @author Anders Rundgren
 */
public class JSONEncryptionHTMLReference extends JSONBaseHTML.Types {
    
    static JSONBaseHTML json;
    static RowInterface row;

    static final String ECDH_PROPERTIES      = "Additional ECDH Properties";
    static final String ECDH_KW_PROPERTIES   = "Additional ECDH+KW Properties";
    static final String RSA_PROPERTIES       = "Additional RSA Encryption Properties";

    static final String ENCRYPTION_OBJECT    = "Encryption Object";
    
    static final String TEST_VECTORS         = "Test Vectors";
    
    static final String SAMPLE_OBJECT        = "Sample Object";
    
    static final String KEY_ENCRYPTION       = "Key Encryption";

    static final String SECURITY_CONSIDERATIONS = "Security Considerations";
 
    static final String CRIT_TEST_VECTOR     = "p256#ecdh-es+a256kw@a256gcm@crit-jwk.json";
    static final String SAMPLE_TEST_VECTOR   = "p256#ecdh-es+a128kw@a128gcm@kid.json";
    static final String SAMPLE_I_TEST_VECTOR = "p256#ecdh-es+a128kw@a128gcm@imp.json";
    static final String SAMPLE_A_TEST_VECTOR = "p256#ecdh-es+a256kw@a128cbc-hs256@kid.json";
    static final String MULT_TEST_VECTOR     = "p256#ecdh-es+a256kw,r2048#rsa-oaep-256@a128cbc-hs256@mult-kid.json";
    static final String GLOB_ALG_TEST_VECTOR = "p256#ecdh-es+a256kw,p384#ecdh-es+a256kw@a128cbc-hs256@mult-glob+alg-kid.json";
    static final String JWK_TEST_VECTOR      = "p256#ecdh-es+a256kw@a128cbc-hs256@jwk.json";
    static final String JKU_TEST_VECTOR      = "p256#ecdh-es+a256kw@a128cbc-hs256@jku.json";
    static final String X5C_TEST_VECTOR      = "p256#ecdh-es+a256kw@a128cbc-hs256@x5c.json";
    static final String X5U_TEST_VECTOR      = "p256#ecdh-es+a256kw@a128cbc-hs256@x5u.json";
    static final String RSA_JWK_TEST_VECTOR  = "r2048#rsa-oaep-256@a256gcm@jwk.json";
    static final String RSA_IMP_TEST_VECTOR  = "r2048#rsa-oaep-256@a256gcm@imp.json";
    static final String RSA_KID_TEST_VECTOR  = "r2048#rsa-oaep-256@a256gcm@kid.json";
    static final String P384_JWK_TEST_VECTOR = "p384#ecdh-es@a256cbc-hs512@jwk.json";
    static final String P521_JWK_TEST_VECTOR = "p521#ecdh-es+a256kw@a128cbc-hs256@jwk.json";
    

    static String enumerateJoseEcCurves() throws IOException  {
        StringBuilder buffer = new StringBuilder("<ul>");
        for (KeyAlgorithms algorithm : KeyAlgorithms.values()) {
            if (algorithm.isECKey()) {
                String joseName = algorithm.getAlgorithmId(AlgorithmPreferences.JOSE_ACCEPT_PREFER);
                if (!joseName.contains (":")) {
                    buffer.append("<li><code>")
                          .append(joseName)
                          .append("</code></li>");
                }
            }
        }
        return buffer.append("</ul>").toString ();
    }

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

    static byte[] dataToEncrypt;
    
    static class CoreKey {
        String keyId;
        String fileName;
        String text;
    }
    
    static Vector<AsymKey> asymmetricKeys = new Vector<AsymKey>();

    static Vector<SymKey> symmetricKeys = new Vector<SymKey>();

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
        asymKey.certPath = json.readJson1(keyType + "certificate.x5c").getJSONArrayReader().getCertificatePath();
        return asymKey;
    }

    static SymKey readSymKey(String keyName) throws IOException {
        SymKey symKey = new SymKey();
        symKey.text = new String(json.readFile1(symKey.fileName = keyName + ".hex"), "utf-8");
        symKey.keyValue = DebugFormatter.getByteArrayFromHex(symKey.text);
        symKey.keyId = keyName;
        return symKey;
    }

    static void scanObject(JSONObjectReader recipient, JSONCryptoHelper.Options options) throws IOException {
        if (recipient.hasProperty(JSONCryptoHelper.KEY_ID_JSON) && 
            options.keyIdOption == JSONCryptoHelper.KEY_ID_OPTIONS.FORBIDDEN) {
            options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.OPTIONAL);
        }
        if (!recipient.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH) &&
                   !recipient.hasProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)) {
            options.setRequirePublicKeyInfo(false);
        }
        if (recipient.hasProperty(JSONCryptoHelper.EXTENSIONS_JSON)) {
            options.setPermittedExtensions(new JSONCryptoHelper.ExtensionHolder()
                .addExtension(Extension1.class, true)
                .addExtension(Extension2.class, true));
        }
    }

    static String validateAsymEncryption (String fileName) throws IOException {
        JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
        JSONObjectReader encryptedObject = json.readJson2(fileName);
        try {
            JSONObjectReader checker = encryptedObject.clone();
            Vector<JSONDecryptionDecoder> recipients = new Vector<JSONDecryptionDecoder>();
            if (checker.hasProperty(JSONCryptoHelper.KEY_ID_JSON)) {
                options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            }
            if (checker.hasProperty(JSONCryptoHelper.RECIPIENTS_JSON)) {
                JSONArrayReader recipientArray = checker.getArray(JSONCryptoHelper.RECIPIENTS_JSON);
                do {
                    scanObject(recipientArray.getObject(), options);
                } while (recipientArray.hasMore());
                recipients = encryptedObject.getEncryptionObjects(options);
            } else {
                scanObject(checker, options);
                recipients.add(encryptedObject.getEncryptionObject(options));
            }
            for (JSONDecryptionDecoder decoder : recipients) {
                String keyId = decoder.getKeyId();
                AsymKey validationKey = null;
                if (keyId != null) {
                    for (AsymKey localKey : asymmetricKeys) {
                        if (keyId.equals(localKey.keyId)) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                PublicKey publicKey = decoder.getPublicKey();
                if (publicKey != null) {
                    for (AsymKey localKey : asymmetricKeys) {
                        if (publicKey.equals(localKey.keyPair.getPublic())) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                X509Certificate[] certPath = decoder.getCertificatePath();
                if (certPath != null) {
                    for (AsymKey localKey : asymmetricKeys) {
                        if (certPath[0].equals(localKey.certPath[0])) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                if (validationKey == null) {
                    for (AsymKey localKey : asymmetricKeys) {
                        if (decoder.getKeyEncryptionAlgorithm().isRsa() ==
                            (localKey.keyPair.getPublic() instanceof RSAPublicKey)) {
                            validationKey = localKey;
                            break;
                        }
                    }
                }
                System.out.println(fileName + " found=" + (validationKey != null));
                if (!ArrayUtil.compare(decoder.getDecryptedData(validationKey.keyPair.getPrivate()), dataToEncrypt)) {
                    throw new IOException(fileName);
                }
            }
        } catch (Exception e) {
            throw new IOException("Failed on file " + fileName + ", " + e.getMessage());
        }
        return encryptedObject.toString();
    }
 
    static X509Certificate[] readCertPath(String name) throws IOException {
        return json.readJson1(name + "certificate.x5c").getJSONArrayReader().getCertificatePath();
    }

    static String aesCrypto(String[] encObjects) throws IOException, GeneralSecurityException {
        StringBuilder s = new StringBuilder();
        for (String name : encObjects) {
            JSONObjectReader rd = json.readJson2(name);
            JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
            if (rd.hasProperty(JSONCryptoHelper.KEY_ID_JSON)) {
                options.setKeyIdOption(JSONCryptoHelper.KEY_ID_OPTIONS.REQUIRED);
            }
            JSONDecryptionDecoder dec = rd.getEncryptionObject(options);
            for (SymKey symKey : symmetricKeys) {
                byte[] key = symKey.keyValue;
                if (key.length == dec.getDataEncryptionAlgorithm().getKeyLength()) {
                    s.append(LINE_SEPARATOR + "AES key");
                    if (dec.getKeyId() != null) {
                        s.append(" named <code>&quot;")
                         .append(symKey.keyId)
                         .append("&quot;</code>");
                    }
                    s.append(" here provided in hexadecimal notation:")
                     .append(formatCode(symKey.text))
                     .append(showTextAndCode("Encryption object requiring the " +
                        (dec.getKeyId() == null ? "<i>implicit</i> " : "") + 
                        "key above for decryption:", name, rd.toString()));
                    if (!ArrayUtil.compare(dec.getDecryptedData(key), dataToEncrypt)) {
                        throw new IOException("Sym enc");
                    }
                    break;
                }
            }
        }
        return s.toString();
    }

    public static void main (String args[]) throws Exception {
        CustomCryptoProvider.forcedLoad(true);

        json = new JSONBaseHTML(args, "JEF - JSON Encryption Format");
        
        json.setFavIcon("../webpkiorg.png");
        
        dataToEncrypt = json.readFile3("datatobeencrypted.txt");
     
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

        JSONObjectReader ecdhEncryption = json.readJson2(SAMPLE_TEST_VECTOR);
        JSONObjectReader authData = ecdhEncryption.clone();
        authData.removeProperty(JSONCryptoHelper.TAG_JSON);
        authData.removeProperty(JSONCryptoHelper.CIPHER_TEXT_JSON);
        String formattedAuthData = authData.serializeToString(JSONOutputFormats.NORMALIZED);
        for (int l = formattedAuthData.length(), j = 0, i = 0; i < l; i++) {
            if (i % 111 == 0 && i > 0) {
                formattedAuthData = formattedAuthData.substring(0, i + j) + 
                        "<br>" + formattedAuthData.substring(i + j);
                j += 4;
            }
        }
        formattedAuthData = formattedAuthData.replace("\"", "&quot;");
        
        json.addParagraphObject().append("<div style=\"margin-top:200pt;margin-bottom:200pt;text-align:center\"><span style=\"" + JSONBaseHTML.HEADER_STYLE + "\">JEF</span>" +
            "<br><span style=\"font-size:" + JSONBaseHTML.CHAPTER_FONT_SIZE + "\">&nbsp;<br>JSON Encryption Format</span></div>");
        
        json.addTOC();

        json.addParagraphObject("Introduction")
          .append("This document specifies a container formatted in JSON ")
          .append(json.createReference(JSONBaseHTML.REF_JSON))
          .append(" for holding encrypted binary data, coined JEF (JSON Encryption Format)." + LINE_SEPARATOR +
            "JEF was derived from IETF's JWE ")
          .append(json.createReference(JSONBaseHTML.REF_JWE))
          .append(
            " specification and supports a <i>subset</i> of the same algorithms ")
          .append(json.createReference(JSONBaseHTML.REF_JWA))
          .append(". Public keys are represented as JWK ")
          .append(json.createReference(JSONBaseHTML.REF_JWK))
          .append(" objects while the encryption container itself utilizes a notation similar to JCS ")
          .append(json.createReference(JSONBaseHTML.REF_JCS))
          .append(" in order to maintain a consistent &quot;style&quot; in applications using encryption and signatures, " +
                  "<i>including providing header information in plain text</i>."
                  + LINE_SEPARATOR +
                  "The JEF encryption scheme is fully compatible with the ES6 ")
          .append(json.createReference(JSONBaseHTML.REF_ES6))
          .append(" JSON/JavaScript serialization and parsing specification.");

        json.addParagraphObject(SAMPLE_OBJECT).append(
              "The following sample object is used to visualize the JEF specification:" +
               formatCode(ecdhEncryption) +
               "The sample object can be decrypted by using the EC private key " +
               "defined in <a href=\"#" + JSONBaseHTML.makeLink(TEST_VECTORS) + 
               "\"><span style=\"white-space:nowrap\">" +
               TEST_VECTORS + "</span></a>.");

        
        json.addDataTypesDescription("JEF containers always start with a top-level JSON object. " + LINE_SEPARATOR);

        json.addProtocolTableEntry("JEF Objects")
          .append("The following tables describe the JEF JSON structures in detail.");
        
        json.addParagraphObject("Operation").append(
                "Prerequisite: A JSON object in accordance with ")
              .append(json.createReference(JSONBaseHTML.REF_JSON))
              .append(" containing properly formatted JEF data." + LINE_SEPARATOR +
                "Parsing restrictions:<ul>" +
                "<li>The original property serialization order <b>must</b> be <i>preserved</i>.</li>" +
                "<li style=\"padding-top:4pt\">There <b>must not</b> be any not here defined properties inside of a JEF object.</li>" +
                "</ul>Since JEF uses the same algorithms as JWE " +
                json.createReference(JSONBaseHTML.REF_JWE) +
                " the JWA " + json.createReference(JSONBaseHTML.REF_JWA) +
                " reference apply with one important exception: <i>Additional Authenticated Data</i> " +
                "used by the symmetric ciphers. " +
                "This difference is due to the way encryption meta-data is formatted. " +
                "The process for creating <i>Additional Authenticated Data</i> is as follows:<ul>" +
                "<li>The <i>top level</i> properties " +
                "<code>" + JSONCryptoHelper.TAG_JSON + "</code> and <code>" + 
                JSONCryptoHelper.CIPHER_TEXT_JSON +
                "</code> (including leading <i>or</i> trailing <code>','</code> characters) " +
                "<b>must</b> " + "be deleted from the JEF object.</li>" +
                "<li style=\"padding-top:4pt\">Whitespace <b>must</b> be removed which in practical terms means removal of all characters outside of quoted strings " +
                "having a value of x09, x0a, x0d or x20.</li>" +
                "<li style=\"padding-top:4pt\">Now the JEF object <b>must</b> be " +
                "<i>recreated</i> using the actual text left after applying the previous measures.</li>" +
                "</ul>" +
                "Applied on the <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_OBJECT) + "\">" + SAMPLE_OBJECT +
                "</a>, a conforming JEF <i>Additional Authenticated Data</i> process should return the following JSON string:" +
                "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>" + formattedAuthData + "</code></div>" +
                "<i>Note that the output string was folded for improving readability</i>. " + LINE_SEPARATOR +
                "The <i>Additional Authenticated Data</i> string is subsequently <span style=\"white-space:nowrap\">UTF-8</span> encoded " +
                "before being applied to the encryption algorithm.");

        json.addParagraphObject(SECURITY_CONSIDERATIONS ).append("This specification does (to the author's " +
        "knowledge), not introduce additional vulnerabilities " +
        "over what is specified for JWE " + json.createReference(JSONBaseHTML.REF_JWE) + ".");

        json.setAppendixMode();

        json.addParagraphObject(TEST_VECTORS).append("This section holds test data which can be used to verify the correctness " +
            "of a JEF implementation." + LINE_SEPARATOR + 
           "All encryption tests encrypt the string below (after first having converted it to UTF-8):" +
           "<div style=\"padding:10pt 0pt 10pt 20pt\"><code>&quot;" + new String(dataToEncrypt, "UTF-8") +
           "&quot;</code></div>" +
           showKey(
               "The <a href=\"#" + JSONBaseHTML.makeLink(SAMPLE_OBJECT) + "\">" + 
               SAMPLE_OBJECT + "</a>" +
               " (available in file <b>" +
               SAMPLE_TEST_VECTOR + 
               "</b>), can be decrypted by the following EC private key, here expressed in the JWK " + 
               json.createReference(JSONBaseHTML.REF_JWK) + " format:", 
               p256key) +
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while using a different set of " +
                           "algorithms both for key encryption and content encryption:" ,
                   SAMPLE_A_TEST_VECTOR) +
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the public key information in line, " +
                           "instead of using a <code>" + JSONCryptoHelper.KEY_ID_JSON + "</code>:",
                    JWK_TEST_VECTOR) + 
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object but assuming it is known through the <i>context</i>:",
                   SAMPLE_I_TEST_VECTOR) + 
           showAsymEncryption("ECDH encryption object <i>requiring the same private key</i> " +
                   "as in the sample object while providing the key information " +
                   "through an in-line certificate path:",
                   X5C_TEST_VECTOR) + 
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the key information " +
                           "through an <i>external</i> certificate path:",
                   X5U_TEST_VECTOR) + 
           showAsymEncryption("ECDH encryption object <i>requiring the same private key</i> " +
                   "as in the sample object while providing the key information " +
                   "through an <i>external</i> public key:",
                   JKU_TEST_VECTOR) + 
           showKeySet (
                   "JWK " + json.createReference(JSONBaseHTML.REF_JWK) +
                   " key set associated with the preceeding encryption object:", 
                   "p256") +
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the same private key</i> " +
                           "as in the sample object while providing the key information " +
                           "in line.  In addition, this object declares <code>" +
                           JSONCryptoHelper.EXTENSIONS_JSON + "</code> extensions:",
                   CRIT_TEST_VECTOR) + 
           showKey(
                   "EC private key for decrypting the subsequent object:",
                    p384key) +
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the private key above</i>:",
                   P384_JWK_TEST_VECTOR) + 
           showKey(
                   "EC private key for decrypting the subsequent object:",
                    p521key) +
           showAsymEncryption(
                   "ECDH encryption object <i>requiring the private key above</i>:",
                   P521_JWK_TEST_VECTOR) + 
           showKey(
                   "RSA private key for decrypting the subsequent object:",
                   r2048key) +
           showAsymEncryption(
                   "RSA encryption object <i>requiring the private key above</i>:",
                   RSA_JWK_TEST_VECTOR) +
            showAsymEncryption(
                   "RSA encryption object <i>requiring the same private key</i> " +
                           "as in the previous example but relying on that this being " +
                           "<i>implicitly known</i> since the encryption object " +
                           "neither contains a <code>" +
                           JSONCryptoHelper.KEY_ID_JSON + "</code>, nor a <code>" +
                           JSONCryptoHelper.PUBLIC_KEY_JSON + "</code> property:",
                   RSA_IMP_TEST_VECTOR) +
           showAsymEncryption(
                   "RSA encryption object <i>requiring the same private key</i> " +
                           "as in the previous example while using a different set of " +
                           "algorithms both for key encryption and content encryption:",
                   RSA_KID_TEST_VECTOR) + 
           showAsymEncryption(
                   "Multiple recipient encryption object <i>requiring the same private keys</i> " +
                   "as in the previous examples:",
                   MULT_TEST_VECTOR) +
           showAsymEncryption(
                   "Multiple recipient encryption object <i>requiring the same private keys</i> " +
                           "as in the previous examples as well as using a <i>global</i> <code>" +
                           JSONCryptoHelper.ALGORITHM_JSON + "</code> property:",
                   GLOB_ALG_TEST_VECTOR) +
           aesCrypto(new String[]{"a128@a128gcm@kid.json",
                                  "a256@a128cbc-hs256@kid.json",
                                  "a256@a256gcm@imp.json",
                                  "a256@a256gcm@kid.json",
                                  "a512@a256cbc-hs512@kid.json"}));

        json.addReferenceTable();
        
        json.addDocumentHistoryLine("2016-08-03", "0.3", "Initial publication in HTML5");
        json.addDocumentHistoryLine("2017-04-19", "0.4", "Changed public keys to use JWK " + json.createReference(JSONBaseHTML.REF_JWK) + " format");
        json.addDocumentHistoryLine("2017-04-25", "0.5", "Added KW and GCM algorithms");
        json.addDocumentHistoryLine("2017-05-15", "0.51", "Added test vectors and missing RSA-OAEP algorithm");
        json.addDocumentHistoryLine("2018-01-15", "0.60", "Rewritten to reuse JWE " + json.createReference(JSONBaseHTML.REF_JWE) + " property names");

        json.addParagraphObject("Author").append("JEF was developed by Anders Rundgren (<code>anders.rundgren.net@gmail.com</code>) as a part " +
                                                 "of the OpenKeyStore " +
                                                 json.createReference(JSONBaseHTML.REF_OPENKEYSTORE) + " project .");

        json.addProtocolTable(ENCRYPTION_OBJECT)
                .newRow()
                    .newColumn()
                        .addProperty(JSONCryptoHelper.ALGORITHM_JSON)
                        .addSymbolicValue("Algorithm")
                    .newColumn()
                        .setType(Types.WEBPKI_DATA_TYPES.STRING)
                    .newColumn()
                    .newColumn()
        .addString("Content encryption algorithm. Currently the following JWE " +
            json.createReference(JSONBaseHTML.REF_JWE) +
            " algorithms are recognized:<ul>")
        .newExtensionRow(new Extender() {
            @Override
            public Column execute(Column column) throws IOException {
                for (DataEncryptionAlgorithms dea : DataEncryptionAlgorithms.values()) {
                    column.addString("<li><code>")
                          .addString(dea.toString())
                          .addString("</code></li>");
                }
                return column;
            }
        })
        .addString("</ul>")
            .newRow()
        .newColumn()
            .addProperty(JSONCryptoHelper.ALGORITHM_JSON)
            .addSymbolicValue("Algorithm")
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 1)
        .newColumn()
            .addString("<i>Optional</i>. See " +
        json.globalLinkRef(KEY_ENCRYPTION, JSONCryptoHelper.ALGORITHM_JSON) +
                   "." + Types.LINE_SEPARATOR +
                   "Note: There <b>must</b> always be an <code>&quot;" + JSONCryptoHelper.ALGORITHM_JSON +
                   "&quot;</code> identifier present. " +
                   "However, for <i>multiple</i> encryptions schemes <code>&quot;" + JSONCryptoHelper.ALGORITHM_JSON +
                   "&quot;</code> can either be provided at the top level (=shared), " +
                   "or be suppled individually (local level) for each encryption object, not both." +
                   Types.LINE_SEPARATOR +
                   JSONBaseHTML.referToTestVector(GLOB_ALG_TEST_VECTOR))
       .newRow()

        .newColumn()
        .addProperty("...")
        .addLink(KEY_ENCRYPTION)
    .newColumn()
        .setType(Types.WEBPKI_DATA_TYPES.SPECIAL)
    .newColumn()
             .setChoice (false, 2)
    .newColumn()
        .addString("If an encryption scheme <i>for a single recipient</i> is targeted, the " +
                   "applicable properties from " +
                json.globalLinkRef(KEY_ENCRYPTION) +
                    " <b>must</b> also be featured inside of the encryption " +
                " object (=at the top level) as illustrated by the " +
                    json.globalLinkRef(SAMPLE_OBJECT) + ".")
       .newRow()
        .newColumn()
        .addProperty(JSONCryptoHelper.RECIPIENTS_JSON)
        .addArrayLink(KEY_ENCRYPTION, 1)
    .newColumn()
        .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
    .newColumn()
    .newColumn()
        .addString("If this property is defined, one or more recipients <b>must</b> each be provided "+
                   "with a suitable " +
                   json.globalLinkRef(KEY_ENCRYPTION) +
                   " object."+ 
                   Types.LINE_SEPARATOR +
                   JSONBaseHTML.referToTestVector(MULT_TEST_VECTOR))
       .newRow()
        .newColumn()
        .addProperty(JSONCryptoHelper.EXTENSIONS_JSON)
          .addArrayList(Types.PROPERTY_LIST, 1)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
          .setChoice (false, 1)
        .newColumn()
          .addString("<i>Optional.</i> Array holding the names of one or more application specific extension properties " +
          "featured in the " +
                  json.globalLinkRef(KEY_ENCRYPTION) +
          " object (or the top level object " +
          "for the case there is no <code>&quot;" + JSONCryptoHelper.RECIPIENTS_JSON + 
          "&quot;</code> element)." +
          Types.LINE_SEPARATOR +
          "Extension names <b>must not</b> be <i>duplicated</i> or use any of the JEF <i>reserved words</i> " +
          JSONBaseHTML.enumerateAttributes(JSONCryptoHelper.jefReservedWords.toArray(new String[0]), false) + ". " +
          Types.LINE_SEPARATOR +
          "Extensions intended for public consumption are <i>preferably</i> expressed as URIs " +
          "(unless registered with IANA), " +
          "while private schemes are free using any valid property name." + Types.LINE_SEPARATOR +
          "A conforming JEF implementation <b>must</b> <i>reject</i> encryption objects listing properties " +
          "that are not found as well as empty <code>&quot;" +
          JSONCryptoHelper.EXTENSIONS_JSON + "&quot;</code> objects. " +
          "Receivers are <i>recommended</i> introducing additional constraints like only accepting predefined extensions." +
          Types.LINE_SEPARATOR +
          JSONBaseHTML.referToTestVector(CRIT_TEST_VECTOR))
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.IV_JSON)
          .addSymbolicValue(JSONCryptoHelper.IV_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Initialization vector.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.TAG_JSON)
          .addSymbolicValue(JSONCryptoHelper.TAG_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Authentication tag.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.CIPHER_TEXT_JSON)
          .addSymbolicValue(JSONCryptoHelper.CIPHER_TEXT_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted data.").setNotes("Note that if neither <code>" + JSONCryptoHelper.KEY_ID_JSON +
                      "</code> nor <code>" + "@@@" + 
                      "</code> are defined, the (symmetric) data encryption key is assumed to known by the recipient.");
          
             json.addSubItemTable(KEY_ENCRYPTION)
                .newRow()
                    .newColumn()
                        .addProperty(JSONCryptoHelper.ALGORITHM_JSON)
                        .addSymbolicValue("Algorithm")
                    .newColumn()
                        .setType(Types.WEBPKI_DATA_TYPES.STRING)
                    .newColumn()
             .setChoice (false, 1)
                    .newColumn()
            .addString("Key encryption algorithm. Currently the following JWE " +
                                json.createReference (JSONBaseHTML.REF_JWE) +
                                " algorithms are recognized:<ul>")
            .newExtensionRow(new Extender() {
                @Override
                public Column execute(Column column) throws IOException {
                    for (KeyEncryptionAlgorithms kea : KeyEncryptionAlgorithms.values()) {
                        column.addString(new StringBuilder("<li>")
                                               .append(JSONBaseHTML.codeVer(kea.toString(), 16)).toString());
                        if (kea.jceName == null) {
                            column.addString("Direct mode" + Types.LINE_SEPARATOR);
                        } else {
                            column.addString("See: ");
                            String link = ECDH_PROPERTIES;
                            if (kea.isRsa()) {
                                link = RSA_PROPERTIES;
                            } else if (kea.isKeyWrap()) {
                                link = ECDH_KW_PROPERTIES;
                            }
                            column.addLink(link);
                        }
                        column.addString("</li>");
                    }
                    return column;
                }
            })
            .addString("</ul>")
      .newRow()
        .newColumn()
            .addProperty(JSONCryptoHelper.KEY_ID_JSON)
           .addSymbolicValue("Key Identifier")
        .newColumn()
            .setType(Types.WEBPKI_DATA_TYPES.STRING)
        .newColumn()
             .setChoice (false, 1)
        .newColumn()
            .addString("If the <code>" + JSONCryptoHelper.KEY_ID_JSON +
                   "</code> property is defined, it is supposed to identify the " +
                    "public key associated with the encrypted (or derived) key.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.PUBLIC_KEY_JSON)
          .addLink (JSONCryptoHelper.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
             .setChoice (false, 4)
        .newColumn()
          .addString("<i>Optional.</i> Public key associated with the encrypted (or derived) key." +
                    Types.LINE_SEPARATOR +
                    JSONBaseHTML.referToTestVector(JWK_TEST_VECTOR))
          .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.CERTIFICATE_PATH)
          .addArrayList(Types.CERTIFICATE_PATH, 1)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY2)
        .newColumn()
        .newColumn()
          .addString("<i>Optional.</i> Sorted array of X.509 ")
          .addString(json.createReference(JSONBaseHTML.REF_X509))
          .addString(" certificates, where the <i>first</i> element <b>must</b> contain the <i style=\"white-space:nowrap\">encryption certificate</i>. " +
                      "The certificate path <b>must</b> be <i>contiguous</i> but is not required to be complete." +
                    Types.LINE_SEPARATOR +
                    JSONBaseHTML.referToTestVector(X5C_TEST_VECTOR))
     .newRow(ECDH_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoHelper.EPHEMERAL_KEY_JSON)
          .addLink (JSONCryptoHelper.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
    .newRow(ECDH_KW_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoHelper.EPHEMERAL_KEY_JSON)
          .addLink (JSONCryptoHelper.PUBLIC_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.OBJECT)
        .newColumn()
        .newColumn()
          .addString("Ephemeral EC public key.")
        .newRow()
        .newColumn()
          .addProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONCryptoHelper.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted content encryption key.")
     .newRow(RSA_PROPERTIES)
        .newColumn()
          .addProperty(JSONCryptoHelper.ENCRYPTED_KEY_JSON)
          .addSymbolicValue(JSONCryptoHelper.ENCRYPTED_KEY_JSON)
        .newColumn()
          .setType(Types.WEBPKI_DATA_TYPES.BYTE_ARRAY)
        .newColumn()
        .newColumn()
          .addString("Encrypted content encryption key.")
              .setNotes("Note that if neither <code>" + JSONCryptoHelper.KEY_ID_JSON +
                "</code> nor <code>" + JSONCryptoHelper.PUBLIC_KEY_JSON + 
                "</code> are defined, the associated key is assumed to known by the recipient.");

        json.AddPublicKeyDefinitions();

        json.writeHTML();
    }

    static String showTextAndCode(String text, String fileName, String code) throws IOException {
        String link = JSONBaseHTML.makeLink(fileName);
        return "<div style=\"cursor:pointer;font-weight:bold;padding:10pt 0 7pt 0\" onclick=\"document.location.href='#" +
               link + "'\" id=\"" + link + 
               "\">" + fileName + "</div>" +
               text + 
               formatCode(code);
    }

    static String showKeySet(String text, String keyType) throws IOException {
        String fileName = keyType + ".jwks";
        JSONObjectReader keySet = json.readJson1(fileName);
        String code = keySet.toString();
        JSONArrayReader keys = keySet.getArray("keys");
        keys.getObject().getCorePublicKey(AlgorithmPreferences.JOSE);
        keySet.checkForUnread();
        return showTextAndCode(text, fileName, code);
    }

    static String showKey(String text, CoreKey key) throws IOException {
        return showTextAndCode(text, key.fileName, key.text);
    }

    static String showAsymEncryption(String text, String encryptionFile) throws IOException {
        return showTextAndCode(text, encryptionFile, validateAsymEncryption(encryptionFile));
    }

}

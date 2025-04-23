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
package org.webpki.webapps.csf_lab;

import java.io.IOException;

import java.net.URLEncoder;

import java.security.PrivateKey;
import java.security.PublicKey;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORAsymKeySigner;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBORHmacSigner;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORSigner;
import org.webpki.cbor.CBORX509Signer;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.json.JSONObjectWriter;

import org.webpki.util.Base64;
import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

public class CreateServlet extends CoreRequestServlet {
    
    private static final long serialVersionUID = 1L;

    static final String DEFAULT_ALG      = "Ed25519";
    static final String DEFAULT_CBOR     = "{\\n" +
                                           "  / just a string /\\n" +
                                           "  1: \"Hello signed world!\",\\n" +
                                           "  / some other data /\\n" +
                                           "  2: [2.0, true]\\n" +
                                           "}";
    
    class SelectAlg {

        String preSelected;
        StringBuilder html = new StringBuilder("<select name='" +
                PRM_ALGORITHM + "' id='" +
                PRM_ALGORITHM + "' onchange=\"algChange(this.value)\">");
        
        SelectAlg(String preSelected) {
            this.preSelected = preSelected;
        }

        SelectAlg add(SignatureAlgorithms algorithmString) throws IOException {
            String algId = algorithmString.getAlgorithmId(AlgorithmPreferences.JOSE);
            String nonPolymorphic = algId;
            if (nonPolymorphic.startsWith("ES")) {
                nonPolymorphic = nonPolymorphic.replace("ES", "ESP");
            }
            html.append("<option value='")
                .append(algId)
                .append("'")
                .append(algId.equals(preSelected) ? " selected>" : ">")
                .append(nonPolymorphic)
                .append("</option>");
            return this;
        }

        @Override
        public String toString() {
            return html.append("</select>").toString();
        }
    }
    
    StringBuilder checkBox(String idName, String text, boolean checked, String onchange) {
        StringBuilder html = new StringBuilder(
                "<div style='display:flex;align-items:center;padding-bottom:0.5em'>" +
                  "<input type='checkbox' id='")
            .append(idName)
            .append("' name='")
            .append(idName)
            .append("'");
        if (checked) {
            html.append(" checked");
        }
        if (onchange != null) {
            html.append(" onchange=\"")
                .append(onchange)
                .append("\"");
        }
        html.append("><div style='display:inline-block'>")
            .append(text)
            .append("</div></div>");
        return html;
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder html = new StringBuilder(
            "<form name='shoot' method='POST' action='create'>" +
            "<div class='header'>CBOR Signature Creation</div>" +
            HTML.fancyText(
                    true,
                    PRM_CBOR_DATA,
                    10,
                    "",
                    DIAG_OR_HEX +
                    "Paste an unsigned CBOR object in the text box or try with the default") +
             "<div style='display:flex;justify-content:center;margin-top:20pt'>" +
             "<div class='sigparmbox'>" +
             "<div style='display:flex;justify-content:center'>" +
               "<div class='sigparmhead'>Signature Parameters</div>" +
             "</div><div style='display:flex;align-items:center;padding-bottom:0.5em'>")
        .append(new SelectAlg(DEFAULT_ALG)
                 .add(HmacAlgorithms.HMAC_SHA256)
                 .add(HmacAlgorithms.HMAC_SHA384)
                 .add(HmacAlgorithms.HMAC_SHA512)
                 .add(AsymSignatureAlgorithms.ED25519)
                 .add(AsymSignatureAlgorithms.ED448)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA256)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA384)
                 .add(AsymSignatureAlgorithms.ECDSA_SHA512)
                 .add(AsymSignatureAlgorithms.RSA_SHA256)
                 .add(AsymSignatureAlgorithms.RSA_SHA384)
                 .add(AsymSignatureAlgorithms.RSA_SHA512)
                 .add(AsymSignatureAlgorithms.RSAPSS_SHA256)
                 .add(AsymSignatureAlgorithms.RSAPSS_SHA384)
                 .add(AsymSignatureAlgorithms.RSAPSS_SHA512)
                 .toString())
        .append(
            "<div style='display:inline-block;padding:0 10pt 0 5pt'>Algorithm</div>" +
            "<div style='margin-left:auto' class='defbtn' onclick=\"restoreDefaults()\">Restore&nbsp;defaults</div></div>")
        .append(checkBox(FLG_PUB_INLINE, "Include public key", false, "pubFlagChange(this.checked)"))
        .append(checkBox(FLG_CERT_PATH, "Include provided certificate path", false, "certFlagChange(this.checked)"))
        .append(
            "<div style='display:flex;align-items:center'>" +
            "<input type='text' name='" + PRM_KEY_ID + "' id='" + PRM_KEY_ID + "' " +
            "class='text' maxlength='100' value=''>" +
            "<div style='display:inline-block'>&nbsp;Optional key Id in " + DIAG_NOT_LINK + "</div></div>" +
            "</div>" +
            "</div>" +
            "<div style='display:flex;justify-content:center'>" +
            "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
            "Create CBOR Signature" +
            "</div>" +
            "</div>")
        .append(HTML.fancyText(
                    false,
                    PRM_SECRET_KEY,
                    1,
                    "",
                    "Secret key in hexadecimal format"))
        .append(HTML.fancyText(
                    false,
                    PRM_PRIVATE_KEY,
                    4,
                    "",
                    "Private key in PEM/PKCS #8, JWK, or COSE format"))
        .append(HTML.fancyText(false,
                    PRM_CERT_PATH,
                    4,
                    "",
                    "Certificate path in PEM format"))
        .append(
            "</form>" +
            "<div>&nbsp;</div>");

        StringBuilder js = new StringBuilder("'use strict';\n")
        .append(CSFService.keyDeclarations)
        .append(
            "function fill(id, alg, keyHolder, unconditionally) {\n" +
            "  let element = document.getElementById(id).children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = keyHolder[alg];\n" +
            "}\n" +
            "function disableAndClearCheckBox(id) {\n" +
            "  let checkBox = document.getElementById(id);\n" +
            "  checkBox.checked = false;\n" +
            "  checkBox.disabled = true;\n" +
            "}\n" +
            "function enableCheckBox(id) {\n" +
            "  document.getElementById(id).disabled = false;\n" +
            "}\n" +
            "function setUserData(unconditionally) {\n" +
            "  let element = document.getElementById('" + PRM_CBOR_DATA + "').children[1];\n" +
            "  if (unconditionally || element.value == '') element.value = '" + DEFAULT_CBOR + "';\n" +
            "}\n" +
            "function setParameters(alg, unconditionally) {\n" +
            "  if (alg.startsWith('HS')) {\n" +
            "    showCert(false);\n" +
            "    showPriv(false);\n" +
            "    disableAndClearCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    disableAndClearCheckBox('" + FLG_PUB_INLINE + "');\n" +
            "    fill('" + PRM_SECRET_KEY + "', alg, " + 
                 CSFService.KeyDeclaration.SECRET_KEYS + ", unconditionally);\n" +
            "    showSec(true)\n" +
            "  } else {\n" +
            "    showSec(false)\n" +
            "    enableCheckBox('" + FLG_CERT_PATH + "');\n" +
            "    enableCheckBox('" + FLG_PUB_INLINE + "');\n" +
            "    fill('" + PRM_PRIVATE_KEY + "', alg, " + 
            CSFService.KeyDeclaration.PRIVATE_KEYS + ", unconditionally);\n" +
            "    showPriv(true);\n" +
            "    fill('" + PRM_CERT_PATH + "', alg, " + 
            CSFService.KeyDeclaration.CERTIFICATES + ", unconditionally);\n" +
            "    showCert(document.getElementById('" + FLG_CERT_PATH + "').checked);\n" +
            "  }\n" +
            "}\n" +
            "function pubFlagChange(flag) {\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "    showCert(false);\n" +
            "  }\n" +
            "}\n" +
            "function certFlagChange(flag) {\n" +
            "  showCert(flag);\n" +
            "  if (flag) {\n" +
            "    document.getElementById('" + FLG_PUB_INLINE + "').checked = false;\n" +
            "  }\n" +
            "}\n" +
            "function setInputMode(flag) {\n" +
            "  document.getElementById('" + PRM_CBOR_DATA + "').children[1].placeholder = flag ? " +
              "'Diagnostic notation' : 'Hexadecimal data';\n" +
            "}\n" +
            "function restoreDefaults() {\n" +
            "  let s = document.getElementById('" + PRM_ALGORITHM + "');\n" +
            "  for (let i = 0; i < s.options.length; i++) {\n" +
            "    if (s.options[i].text == '" + DEFAULT_ALG + "') {\n" +
            "      s.options[i].selected = true;\n" +
            "      break;\n" +
            "    }\n" +
            "  }\n" +
            "  setParameters('" + DEFAULT_ALG + "', true);\n" +
            "  document.getElementById('" + FLG_DIAGNOSTIC + "').checked = true;\n" +
            "  document.getElementById('" + FLG_CERT_PATH + "').checked = false;\n" +
            "  document.getElementById('" + FLG_PUB_INLINE + "').checked = false;\n" +
            "  document.getElementById('" + PRM_KEY_ID + "').value = '';\n" +
            "  showCert(false);\n" +
            "  setUserData(true);\n" +
            "}\n" +
            "function algChange(alg) {\n" +
            "  setParameters(alg, true);\n" +
            "}\n" +
            "function showCert(show) {\n" +
            "  document.getElementById('" + PRM_CERT_PATH + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showPriv(show) {\n" +
            "  document.getElementById('" + PRM_PRIVATE_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "function showSec(show) {\n" +
            "  document.getElementById('" + PRM_SECRET_KEY + "').style.display= show ? 'block' : 'none';\n" +
            "}\n" +
            "window.addEventListener('load', function(event) {\n" +
            "  setParameters(document.getElementById('" + PRM_ALGORITHM + "').value, false);\n" +
            "  setUserData(false);\n" +
            "  setInputMode(true);\n" +
            "});\n");

        HTML.standardPage(response, js.toString(), html);
    }
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
         try {
            request.setCharacterEncoding("utf-8");
            final CBORObject rawCbor = (Boolean.valueOf(getParameter(request, PRM_INPUT_TYPE)) ? 
                CBORDiagnosticNotation.convert(getParameterTextarea(request, PRM_CBOR_DATA))
                                    :
                getCborFromHex(getParameter(request, PRM_CBOR_DATA)));
            
            // This is certainly not something you would do in a normal case...
            
            boolean keyInlining = request.getParameter(FLG_PUB_INLINE) != null;
            boolean certOption = request.getParameter(FLG_CERT_PATH) != null;
            
            // Mandatory algorithm
            String algorithmString = getParameter(request, PRM_ALGORITHM);
            
            // Get optional key Id
            String optionalKeyIdString = getParameter(request, PRM_KEY_ID);
            CBORObject optionalKeyId = optionalKeyIdString.length() == 0 ? null :
                getCborAttribute(optionalKeyIdString,
                        "Key Ids must be in CBOR diagnostic notation like \"mykey\" or 31");
 
            // Get the signature key
            CBORSigner<?> signer;
            String validationKey;
            
            // Symmetric or asymmetric?
            if (algorithmString.startsWith("HS")) {
                validationKey = getParameter(request, PRM_SECRET_KEY);
                signer = new CBORHmacSigner(
                        HexaDecimal.decode(validationKey),
                        HmacAlgorithms.getAlgorithmFromId(algorithmString, 
                                                          AlgorithmPreferences.JOSE));
            } else {
                // To simplify UI we require PKCS #8 with the public key embedded
                // but we also support JWK and COSE which also has the public key
                ReadKeyData keyData = extractKeyData(getParameter(request,
                                                                  PRM_PRIVATE_KEY),
                                                                  RequestedKeyType.KEYPAIR);
                PublicKey publicKey = keyData.keyPair.getPublic();
                PrivateKey privateKey = keyData.keyPair.getPrivate();
                if (keyData.jwkKey) {
                    validationKey = JSONObjectWriter.createCorePublicKey(publicKey,
                        AlgorithmPreferences.JOSE).toString();
                } else if (keyData.coseKey) {
                    validationKey = CBORPublicKey.convert(publicKey).toString();
                } else {
                    validationKey = "-----BEGIN PUBLIC KEY-----\n" +
                                    Base64.mimeEncode(publicKey.getEncoded()) +
                                    "\n-----END PUBLIC KEY-----";
                }

                // Create asymmetric key signer 
                AsymSignatureAlgorithms asymSignatureAlgorithm =
                        AsymSignatureAlgorithms.getAlgorithmFromId(algorithmString,
                                                                   AlgorithmPreferences.JOSE);
                if (certOption) {
                    signer = new CBORX509Signer(
                            privateKey,
                            PEMDecoder.getCertificatePath(getBinaryParameter(request, PRM_CERT_PATH)),
                            asymSignatureAlgorithm);
                } else {
                    signer = new CBORAsymKeySigner(privateKey, asymSignatureAlgorithm)
                                .setPublicKey(keyInlining ? publicKey : null);
                }
            }

            signer.setKeyId(optionalKeyId);

            // Finally, sign!
            CBORObject signedCborObject = signer.sign(rawCbor);

            // We terminate by validating the signature as well
            request.getRequestDispatcher("validate?" +
                CSF_OBJECT_IN_HEX +
                "=true&" +
                CSF_OBJECT + 
                "=" +
                HexaDecimal.encode(signedCborObject.encode()) +
                "&" +
                CSF_VALIDATION_KEY + 
                "=" +
                URLEncoder.encode(validationKey, "utf-8"))
                    .forward(request, response);
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }
}

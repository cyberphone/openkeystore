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
package org.webpki.webapps.csf_lab;

import java.io.IOException;

import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.security.cert.X509Certificate;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORHmacValidator;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORTypes;
import org.webpki.cbor.CBORX509Validator;
import org.webpki.cbor.CBORCryptoConstants;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CertificateInfo;

import org.webpki.json.JSONParser;

import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

public class ValidateServlet extends CoreRequestServlet {

    private static final long serialVersionUID = 1L;

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            // Get the input data items
            CBORObject signedCborObject = (Boolean.valueOf(getParameter(request, CSF_OBJECT_IN_HEX)) ?
                    hexDecodedCbor(getParameter(request, CSF_OBJECT))
                                                :
                    CBORDiagnosticParser.parse(getParameterTextarea(request, CSF_OBJECT)));
            String validationKey = getParameter(request, CSF_VALIDATION_KEY);
            CBORObject signatureLabel = getSignatureLabel(request);
            
            // This is certainly not what you would do in an application...
            CBORMap signatureObject = (signedCborObject.getType() == CBORTypes.TAGGED_OBJECT ?
                    signedCborObject.getTaggedObject(signedCborObject.getTagNumber()) 
                                                  :
                    signedCborObject).getMap().getObject(signatureLabel).getMap();
            boolean hmacSignature = 
                    signatureObject.getObject(CBORCryptoConstants.ALGORITHM_LABEL).getInt() > 0;
            boolean x509flag = signatureObject.hasKey(CBORCryptoConstants.CERT_PATH_LABEL);
            final StringBuilder certificateData = x509flag ? new StringBuilder() : null;

            // Validation
            boolean jwkValidationKey = validationKey.startsWith("{");
            if (hmacSignature) {
                new CBORHmacValidator(HexaDecimal.decode(validationKey))
                    .validate(signatureLabel, signedCborObject);
            } else {
                PublicKey externalPublicKey =  jwkValidationKey ? 
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    PEMDecoder.getPublicKey(validationKey.getBytes("utf-8"));
                if (x509flag) {

                    new CBORX509Validator(new CBORX509Validator.SignatureParameters() {

                    @Override
                    public void check(X509Certificate[] certificatePath,
                                      AsymSignatureAlgorithms asymSignatureAlgorithm)
                            throws IOException, GeneralSecurityException {
                        for (X509Certificate certificate : certificatePath) {
                            if (!certificatePath[0].getPublicKey().equals(externalPublicKey)) {
                                throw new IOException("Externally supplied public key does not " +
                                                      "match signature certificate");
                            }
                            if (!certificateData.isEmpty()) {
                                certificateData.append("\n\n");
                            }
                            certificateData.append(new CertificateInfo(certificate).toString()
                                                       .replace("  ", ""));
                        }
                    }

                }).validate(signatureLabel, signedCborObject);
                        
                } else {
                    new CBORAsymKeyValidator(externalPublicKey).validate(signatureLabel, 
                                                                         signedCborObject);
                }
            }
            StringBuilder html = new StringBuilder(
                    "<div class='header'> Signature Successfully Validated</div>")
                .append(HTML.fancyBox(
                            CSF_OBJECT,
                            signedCborObject.toString(),
                            "Signed CBOR object in diagnostic notation"))           
                .append(HTML.fancyBox(
                            "inhex",
                            HexaDecimal.encode(signedCborObject.encode()), 
                            "Signed CBOR object in hexadecimal notation"))           
                .append(HTML.fancyBox(
                            CSF_VALIDATION_KEY,
                            jwkValidationKey ? 
                                JSONParser.parse(validationKey).toString()
                                             :
                                validationKey,
                            "Signature validation " + 
                            (hmacSignature ? 
                                   "secret key in hexadecimal" :
                                   "public key in " + 
                                   (jwkValidationKey ? "JWK" : "PEM") +
                                   " format")));
            if (certificateData != null) {
                html.append(HTML.fancyBox(
                                "certpath", 
                                certificateData.toString(),
                                "Core certificate data"));
            }

            // Finally, print it out
            HTML.standardPage(response, null, html.append("<div style='padding:10pt'></div>"));
        } catch (Exception e) {
            HTML.errorPage(response, e);
        }
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder js = new StringBuilder(
                "'use strict';\n" +
                "function setInputMode(flag) {\n" +
                "  console.log('mode=' + flag);\n" +
                "  document.getElementById('" + CSF_OBJECT + "').children[1].placeholder = flag ? " +
                  "'Diagnostic notation' : 'Hexadecimal data';\n" +
                "}\n" +
                "function doVerify() {\n" +
                "  document.getElementById('" + CSF_OBJECT_IN_HEX + 
                    "').value = (!document.getElementById('" + FLG_DIAGNOSTIC +
                    "').checked).toString();\n" +
                 "  document.forms.shoot.submit();\n" +
                "}\n");

        StringBuilder html = new StringBuilder(
                "<form name='shoot' method='POST' action='validate'>" +
                "<input type='hidden' name='" + CSF_OBJECT_IN_HEX + "' id='" + CSF_OBJECT_IN_HEX + "'>" +
                "<div class='header'>CBOR Signature Validation</div>")
            .append(HTML.fancyText(
                        true,
                        CSF_OBJECT,
                        10, 
                        CSFService.sampleSignature,
                        DIAG_OR_HEX +
                        "Paste a signed CBOR object in the text box or try with the default"))
            .append(HTML.fancyText(
                        true,
                        CSF_VALIDATION_KEY,
                        4, 
                        CSFService.samplePublicKey,
"Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))
            .append(HTML.fancyText(
                        true,
                        CSF_SIGN_LABEL,
                        1, 
                        CSFService.sampleLabel,
                        "Anticipated signature label in <i>diagnostic notation</i>"))
            .append(
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"doVerify()\">" +
                "Validate CBOR Signature" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>");
        HTML.standardPage(response, js.toString(), html);
    }
}

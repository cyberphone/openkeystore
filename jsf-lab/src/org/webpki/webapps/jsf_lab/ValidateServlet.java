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
package org.webpki.webapps.jsf_lab;

import java.io.IOException;

import java.security.PublicKey;

import java.security.cert.X509Certificate;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CertificateInfo;

import org.webpki.json.JSONAsymKeyVerifier;
import org.webpki.json.JSONCryptoHelper;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.json.JSONSignatureDecoder;
import org.webpki.json.JSONHmacVerifier;

import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;

public class ValidateServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(ValidateServlet.class.getName());

    // HTML form arguments
    static final String JSF_OBJECT         = "jsf";

    static final String JSF_VALIDATION_KEY = "vkey";
    
    static final String JSF_SIGN_LABL      = "siglbl";
    
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            logger.info("JSON Signature Verification Entered");
            // Get the two input data items
            JSONObjectReader signedJsonObject = JSONParser.parse(
                    CreateServlet.getParameter(request, JSF_OBJECT));
            String validationKey = CreateServlet.getParameter(request, JSF_VALIDATION_KEY);
            String signatureLabel = CreateServlet.getParameter(request, JSF_SIGN_LABL);

            // Create a pretty-printed JSON object without canonicalization
            String prettySignature = 
                    signedJsonObject.serializeToString(JSONOutputFormats.PRETTY_HTML);
            
            // Start decoding by retrieving the signature object
            JSONObjectReader signatureObject = signedJsonObject.getObject(signatureLabel);
            String algorithmString = signatureObject.getString(JSONCryptoHelper.ALGORITHM_JSON);
            StringBuilder certificateData = null;
            JSONCryptoHelper.Options options = new JSONCryptoHelper.Options();
            if (CreateServlet.isSymmetric(algorithmString)) {
                options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.FORBIDDEN);
            } else {
                if (signatureObject.hasProperty(JSONCryptoHelper.CERTIFICATE_PATH_JSON)) {
                    options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.CERTIFICATE_PATH);
                    for (X509Certificate certificate : signatureObject.getCertificatePath()) {
                        if (certificateData == null) {
                            certificateData = new StringBuilder();
                        } else {
                            certificateData.append("<br>&nbsp;<br>");
                        }
                        certificateData.append(
                            HTML.encode(new CertificateInfo(certificate).toString())
                                .replace("\n", "<br>").replace("  ", ""));
                    }
                } else {
                    options.setPublicKeyOption(JSONCryptoHelper.PUBLIC_KEY_OPTIONS.OPTIONAL);
                }
            }
            JSONSignatureDecoder signatureDecoder = 
                    signedJsonObject.getSignature(signatureLabel, options);

            // Final validation
            boolean jwkValidationKey = validationKey.startsWith("{");
            if (CreateServlet.isSymmetric(algorithmString)) {
                signatureDecoder.verify(
                        new JSONHmacVerifier(HexaDecimal.decode(validationKey)));
            } else {
                PublicKey externalPublicKey =  jwkValidationKey ? 
                    JSONParser.parse(validationKey).getCorePublicKey(AlgorithmPreferences.JOSE)
                                                                :
                    PEMDecoder.getPublicKey(validationKey.getBytes("utf-8"));
                    if (certificateData == null) {
                        signatureDecoder.verify(new JSONAsymKeyVerifier(externalPublicKey));
                    } else if (!signatureDecoder.getCertificatePath()[0]
                            .getPublicKey().equals(externalPublicKey)) {
                        throw new IOException("Externally supplied public key does not " +
                                              "match signature certificate");
                    }
            }
            StringBuilder html = new StringBuilder(
                    "<div class='header'> Signature Successfully Validated</div>")
                .append(HTML.fancyBox("signed", prettySignature, "Signed JSON object"))           
                .append(HTML.fancyBox("vkey",
                                      jwkValidationKey ? 
                                          JSONParser.parse(validationKey)
                                              .serializeToString(JSONOutputFormats.PRETTY_HTML)
                                                       :
                                      HTML.encode(validationKey).replace("\n", "<br>"),
                                      "Signature validation " + 
                                      (CreateServlet.isSymmetric(algorithmString) ? 
                                             "secret key in hexadecimal" :
                                             "public key in " + 
                                             (jwkValidationKey ? "JWK" : "PEM") +
                                             " format")))
                .append(HTML.fancyBox("canonical", 
                                      HTML.encode(new String(signatureDecoder.getNormalizedData(),
                                                  "utf-8")),
                                      "Canonical version of the signed data (with possible line breaks " +
                                      "for display purposes only)"));
            if (certificateData != null) {
                html.append(HTML.fancyBox("certpath", 
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

        HTML.standardPage(response, null, new StringBuilder(
                "<form name='shoot' method='POST' action='validate'>" +
                "<div class='header'>JSON Signature Validation</div>")
            .append(HTML.fancyText(true,
                JSF_OBJECT,
                10, 
                HTML.encode(JSFService.sampleSignature),
                "Paste a signed JSON object in the text box or try with the default"))
            .append(HTML.fancyText(true,
                JSF_VALIDATION_KEY,
                4, 
                HTML.encode(JSFService.samplePublicKey),
"Validation key (secret key in hexadecimal or public key in PEM or &quot;plain&quot; JWK format)"))
            .append(HTML.fancyText(true,
                JSF_SIGN_LABL,
                1, 
                HTML.encode(CreateServlet.DEFAULT_SIG_LBL),
                "Anticipated signature label"))
            .append(
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"document.forms.shoot.submit()\">" +
                "Validate JSON Signature" +
                "</div>" +
                "</div>" +
                "</form>" +
                "<div>&nbsp;</div>"));
    }
}

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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.logging.Logger;

import javax.servlet.ServletOutputStream;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORArray;
import org.webpki.cbor.CBORCryptoConstants;
import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBORException;
import org.webpki.cbor.CBORKeyPair;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORPublicKey;
import org.webpki.cbor.CBORTag;

import org.webpki.crypto.AlgorithmPreferences;

import org.webpki.jose.JOSEKeyWords;
import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;
import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;
import org.webpki.util.PEMDecoder;
import org.webpki.util.UTF8;


public class CoreRequestServlet extends HttpServlet {
    
    static Logger logger = Logger.getLogger(CoreRequestServlet.class.getName());

    private static final long serialVersionUID = 1L;

    // Common UI constants
    static final String CSF_OBJECT         = "csf";

    static final String CSF_VALIDATION_KEY = "vkey";
    
    static final String CSF_SIGN_LABEL     = "siglbl";

    static final String CSF_OBJECT_IN_HEX  = "inhex";

    static final String PRM_CBOR_DATA      = "cbor";
    
    static final String PRM_INPUT_TYPE     = "intyp";
    static final String FLG_DIAGNOSTIC     = "diag";
    
    // Create UI constants
    static final String PRM_SECRET_KEY     = "sec";

    static final String PRM_PRIVATE_KEY    = "priv";

    static final String PRM_CERT_PATH      = "cert";

    static final String PRM_KEY_ID         = "kid";

    static final String PRM_ALGORITHM      = "alg";

    static final String FLG_CERT_PATH      = "cerflg";
    static final String FLG_PUB_INLINE     = "pubflg";
    
    static final String DIAG_NOT_LINK      = "<a href='" +
                                             "https://cyberphone.github.io/javaapi/org/webpki/" +
                                             "cbor/package-summary.html#diagnostic-notation' " +
                                             "target='_blank' " +
                                             "title='Documentation'>Diagnostic Notation</a>";
    
    static final String DETERMINISTIC_LINK = "<a href='" +
                                             "https://cyberphone.github.io/javaapi/org/webpki/" +
                                             "cbor/package-summary.html#deterministic-encoding' " +
                                             "target='_blank' " +
                                             "title='Documentation'>Deterministic Encoding</a>";

    static final String DIAG_OR_HEX = 
            "<table style='margin-bottom:0.3em;border-spacing:0'>" +
            "<tr><td><input type='radio' id='" + FLG_DIAGNOSTIC + 
            "' name='" + PRM_INPUT_TYPE + "' " +
            "checked onchange='setInputMode(true)' value='true'></td>" +
            "<td>" + DIAG_NOT_LINK + "</td>" +
            "<td><input type='radio' name='" + PRM_INPUT_TYPE + "' " +
            "onchange='setInputMode(false)' value='false'></td> " +
            "<td>Hexadecimal notation (including possible #-comments)</td></tr>" +
            "</table>";

    // Key and CBOR conversion
    static final String CBOR_OUT                = "cborout";
    static final String ERROR                   = "error";
    
    static final String SEL_OUT                 = "selout";
    
    static final String DIAG                    = "diag";
    static final String HEXA                    = "hexa";
    static final String CSTYLE                  = "cstyle";
    static final String B64U                    = "b64u";
    static final String SEQUENCE_FLAG           = "seqfl";
    static final String STRICT_FLAG             = "strict";
    static final String REJECT_NAN_FLAG         = "nonan";
    
    // HTTP
    static final String HTTP_PRAGMA              = "Pragma";
    static final String HTTP_EXPIRES             = "Expires";
    static final String HTTP_ACCEPT_HEADER       = "Accept";
    static final String HTTP_CONTENT_TYPE_HEADER = "Content-Type";
    static final String JSON_CONTENT_TYPE        = "application/json";
    

    
    String selector(String name, boolean input) {
        return
            "<table style='margin-bottom:0.3em;border-spacing:0'>" +
            "<tr><td style='padding-right:1em'><input type='radio' name='" + name + "' " +
            "value='" + DIAG + "'" + (input ? " checked" : "") + 
              "></td><td>" + DIAG_NOT_LINK + "</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + HEXA + "'" + (input ? "" : " checked") +
            "></td><td>Hexadecimal notation" + (input ? " (including possible #-comments)" 
                                                        : "") + "</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + CSTYLE + "'></td><td><code>0xhh, 0xhh...</code> notation</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + B64U + "'></td><td>Base64Url notation</td></tr>" +
            (input ? "<tr><td><input type='checkbox' id='" + SEQUENCE_FLAG + "'>" +
                    "</td><td>Sequence using comma (,) as separator</td></tr>" +
                    "<tr><td><input type='checkbox' checked id='" + STRICT_FLAG + "'>" +
                    "</td><td>Require " + DETERMINISTIC_LINK + " for hex/b64u data</td></tr>" +
                    "<tr><td><input type='checkbox' id='" + REJECT_NAN_FLAG + "'>" +
                    "</td><td>Reject <code>NaN</code> and <code>Infinity</code> floating point objects</td></tr>" 
                    : "") + 
            "</table>";
    }

    String getParameterTextarea(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.replace("\r\n", "\n");
    }

    String getParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameterTextarea(request, parameter).trim();
    }

    byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return UTF8.encode(getParameter(request, parameter));
    }

    byte[] getBytesFromCborHex(String hexAndOptionalComments) throws IOException {
        return HexaDecimal.decode(
                hexAndOptionalComments.replaceAll("#.*(\r|\n|$)", "")
                                      .replaceAll("( |\n|\r)", ""));
    }
    
    byte[] getBytesFromCborSequence(CBORObject[] cborObjects) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        for (CBORObject cborObject : cborObjects) {
            baos.write(cborObject.encode());
        }
        return baos.toByteArray();        
    }

    String getFormattedCbor(JSONObjectReader parsedJson, CBORObject[] cborObjects) 
            throws IOException {
        String selected = parsedJson.getString(SEL_OUT);
        if (selected.equals(DIAG)) {
            boolean next = false;
            StringBuilder diagnosticNotation = new StringBuilder();
            for (CBORObject cborObject : cborObjects) {
                if (next) {
                    diagnosticNotation.append(",\n");
                }
                next = true;
                diagnosticNotation.append(cborObject.toString());
            }
            return HTML.encode(diagnosticNotation.toString()).replace("\n", "<br>")
                                                             .replace(" ","&nbsp;");
        } else {
            byte[] cborBytes = getBytesFromCborSequence(cborObjects);
            switch (selected) {
                case HEXA:
                    return HexaDecimal.encode(cborBytes);
                    
                case CSTYLE:
                    String hex = HexaDecimal.encode(cborBytes);
                    StringBuilder cstyle = new StringBuilder();
                    for (int i = 0; i < hex.length(); ) {
                        if (i > 0) {
                            cstyle.append(", ");
                        }
                        cstyle.append("0x").append(hex.charAt(i++)).append(hex.charAt(i++));
                    }
                    return cstyle.toString();
    
                default:
                    return Base64URL.encode(cborBytes);
            }
        }
    }

    CBORObject getCborFromHex(String hexAndOptionalComments) throws IOException {
        return CBORDecoder.decode(getBytesFromCborHex(hexAndOptionalComments));
    }

    CBORObject getCborAttribute(String attribute, String errorHelpText) throws IOException {
        try {
            return CBORDiagnosticNotation.convert(attribute);
        } catch (CBORException e) {
            throw new IOException(e.getMessage() + "\n\n" + errorHelpText);
        }   
    }

    CBORObject getSignatureLabel(HttpServletRequest request) throws IOException {
        return getCborAttribute(getParameter(request, CSF_SIGN_LABEL),
                "Signature labels must be in CBOR diagnostic notation like \"sig\" or 8");
    }
    
    CBORMap unwrapOptionalTag(CBORObject rawContainer) throws IOException {
        // It might be tagged
        if (rawContainer instanceof CBORTag) {
            CBORObject container = rawContainer.getTag().getTaggedObject();
            if (container instanceof CBORArray) {
                container = container.getArray().get(1);
            }
            return container.getMap();
        }
        return rawContainer.getMap();
    }

    static class ReadKeyData {
        String optionalKeyId;
        KeyPair keyPair;
        PublicKey publicKey;
        String rewrittenKey;
        boolean jwkKey;
        boolean coseKey;
    }

    enum RequestedKeyType {PUBLIC, KEYPAIR, ANY};
    
    ReadKeyData extractKeyData(String keyDataText, RequestedKeyType requestedKeyType)
                throws IOException {
        ReadKeyData keyData = new ReadKeyData();
        if (keyDataText.startsWith("{")) {
            if (keyDataText.contains("\"kty\"")) {
                keyData.jwkKey = true;
                JSONObjectReader jwk = JSONParser.parse(keyDataText);
                if (jwk.hasProperty(JOSEKeyWords.KID_JSON)) {
                    keyData.optionalKeyId = jwk.getString(JOSEKeyWords.KID_JSON);
                    jwk.removeProperty(JOSEKeyWords.KID_JSON);
                }
                keyData.rewrittenKey = jwk.toString();
                try {
                    keyData.keyPair = jwk.getKeyPair(AlgorithmPreferences.JOSE);
                } catch (Exception e) {
                    keyData.publicKey = jwk.getCorePublicKey(AlgorithmPreferences.JOSE);
                }
            } else {
                keyData.coseKey = true;
                CBORMap cbor = CBORDiagnosticNotation.convert(keyDataText).getMap();
                if (cbor.containsKey(CBORCryptoConstants.COSE_KID_LBL)) {
                    cbor.remove(CBORCryptoConstants.COSE_KID_LBL);
                }
                keyData.rewrittenKey = cbor.toString();
                try {
                    keyData.keyPair = CBORKeyPair.convert(cbor);
                } catch (Exception e) {
                    keyData.publicKey = CBORPublicKey.convert(cbor);
                }
            }
        } else {
            keyData.rewrittenKey = keyDataText;
            byte[] keyInBinary = UTF8.encode(keyDataText);
            try {
                keyData.keyPair = PEMDecoder.getKeyPair(keyInBinary);
            } catch (Exception e) {
                keyData.publicKey = PEMDecoder.getPublicKey(keyInBinary);
            }
        }
        if (keyData.publicKey != null && requestedKeyType == RequestedKeyType.KEYPAIR) {
            throw new IOException("Unexpected public key:\n" + keyData.rewrittenKey);
        } 
        if (keyData.keyPair != null && requestedKeyType == RequestedKeyType.PUBLIC) {
            throw new IOException("Unexpected private key:\n" + keyData.rewrittenKey);
        } 
        return keyData;
    }

    void returnJSON(HttpServletResponse response, JSONObjectWriter json) throws IOException {
        byte[] rawData = json.serializeToBytes(JSONOutputFormats.NORMALIZED);
        response.setContentType(JSON_CONTENT_TYPE);
        response.setHeader(HTTP_PRAGMA, "No-Cache");
        response.setDateHeader(HTTP_EXPIRES, 0);
        // Chunked data seems unnecessary here
        response.setContentLength(rawData.length);
        ServletOutputStream serverOutputStream = response.getOutputStream();
        serverOutputStream.write(rawData);
        serverOutputStream.flush();
    }
}

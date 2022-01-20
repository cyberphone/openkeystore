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

import java.util.logging.Logger;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;

import org.webpki.cbor.CBORObject;


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
    
    static final String DIAG_OR_HEX = 
            "<table style='margin-bottom:0.3em;border-spacing:0'>" +
            "<tr><td><input type='radio' id='" + FLG_DIAGNOSTIC + 
            "' name='" + PRM_INPUT_TYPE + "' " +
            "checked onchange='setInputMode(true)' value='true'></td>" +
            "<td>Diagnostic notation</td>" +
            "<td><input type='radio' name='" + PRM_INPUT_TYPE + "' " +
            "onchange='setInputMode(false)' value='false'></td> " +
            "<td>Hexadecimal notation</td></tr>" +
            "</table>";
    
 
    String getParameter(HttpServletRequest request, String parameter) throws IOException {
        String string = request.getParameter(parameter);
        if (string == null) {
            throw new IOException("Missing data for: "+ parameter);
        }
        return string.trim();
    }
    
    byte[] getBinaryParameter(HttpServletRequest request, String parameter) throws IOException {
        return getParameter(request, parameter).getBytes("utf-8");
    }

    String getTextArea(HttpServletRequest request, String name)
            throws IOException {
        String string = getParameter(request, name);
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }

    CBORObject getSignatureLabel(HttpServletRequest request) throws IOException {
         try {
            return CBORDiagnosticParser.parse(getParameter(request, CSF_SIGN_LABEL));
        } catch (IOException e) {
            throw new IOException("Signature labels must be in CBOR diagnostic " +
                    "notation like \"sig\" or 8");
        }        
    }
}

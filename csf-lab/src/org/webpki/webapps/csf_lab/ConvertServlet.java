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

import java.io.ByteArrayInputStream;
import java.io.IOException;

import java.util.ArrayList;
import java.util.GregorianCalendar;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORDecoder;
import org.webpki.cbor.CBORDiagnosticNotation;
import org.webpki.cbor.CBORObject;
import org.webpki.cbor.CBORSequenceBuilder;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;
import org.webpki.util.ISODateTime;

import org.webpki.webutil.ServletUtil;

public class ConvertServlet extends CoreRequestServlet {

    private static final long serialVersionUID = 1L;
    
    static final String CBOR_IN     = "cborin";
    static final String SEL_IN      = "selin";

        
    byte[] getBytesFromCborSequence(ArrayList<CBORObject> cborObjects) throws IOException {
        CBORSequenceBuilder sequence = new CBORSequenceBuilder();
        for (CBORObject cborObject : cborObjects) {
            sequence.add(cborObject);
        }
        return sequence.encode();        
    }
        
    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        JSONObjectWriter jsonResponse = new JSONObjectWriter();
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().equals("application/json")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            JSONObjectReader parsedJson = JSONParser.parse(ServletUtil.getData(request));
            boolean sequenceFlag = parsedJson.getBoolean(SEQUENCE_FLAG);
            boolean strictFlag = parsedJson.getBoolean(STRICT_FLAG);
            boolean rejectNaNFlag = parsedJson.getBoolean(REJECT_NAN_FLAG);
            String inData = parsedJson.getString(CBOR_IN);
            byte[] cborBytes;
            switch (parsedJson.getString(SEL_IN)) {
                case DIAG:
                    cborBytes = sequenceFlag ?
                        getBytesFromCborSequence(CBORDiagnosticNotation.convertSequence(inData))
                                             :
                        CBORDiagnosticNotation.convert(inData).encode();
                    break;
    
                case CSTYLE:
                    inData = inData.toLowerCase().replace("0x", "").replace(',', ' ');
                case HEXA:
                    cborBytes = getBytesFromCborHex(inData);
                    break;
    
                default:
                    cborBytes = Base64URL.decode(inData);
                    break;
            }
            CBORSequenceBuilder sequence = new CBORSequenceBuilder();
            ByteArrayInputStream bais = new ByteArrayInputStream(cborBytes);
            CBORObject cborObject;
            CBORDecoder cborDecoder = new CBORDecoder(bais, 
                (sequenceFlag ? CBORDecoder.SEQUENCE_MODE : 0) |
                (strictFlag ? 0 :
                     CBORDecoder.LENIENT_MAP_DECODING | CBORDecoder.LENIENT_NUMBER_DECODING) |
                (rejectNaNFlag ? CBORDecoder.REJECT_INVALID_FLOATS : 0),
                                                      cborBytes.length);
            while ((cborObject = cborDecoder.decodeWithOptions()) != null) {
                sequence.add(cborObject);
                if (!sequenceFlag) {
                    break;
                }
            }
            jsonResponse.setString(CBOR_OUT, getFormattedCbor(parsedJson, sequence));
        } catch (Exception e) {
            jsonResponse.setString(ERROR, HTML.encode(e.getMessage()).replace("\n", "<br>")
                                                                     .replace(" ","&nbsp;"));
        }
        returnJSON(response, jsonResponse);
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        StringBuilder js = new StringBuilder(
                "'use strict';\n" +
                "function getRadioValue(name) {\n" +
                "  let ele = document.getElementsByName(name);\n" +
                "  for (var i = 0; i < ele.length; i++) {\n" +
                "    if (ele[i].checked) {\n" +
                "      return ele[i].value;\n" +
                "    }\n" +
                "  }\n" +
                "}\n" +

                "async function delayedConvert() {\n" +
                "  document.getElementById('" + CBOR_OUT + "').children[1].innerHTML = 'Working...';\n" +
                "  setTimeout(function() {\n" +
                "    doConvert();\n" +
                "  }, 200);\n" +
                "}\n" +
                "async function doConvert() {\n" +
                "  let jsonObject = {" +
                   CBOR_IN + ": document.getElementById('" + CBOR_IN + "').children[1].value," +
                   SEL_IN + ": getRadioValue('" + SEL_IN + "')," +
                   SEL_OUT + ": getRadioValue('" + SEL_OUT + "')," +
                   SEQUENCE_FLAG + ": document.getElementById('" + SEQUENCE_FLAG + "').checked," +
                   STRICT_FLAG + ": document.getElementById('" + STRICT_FLAG + "').checked," +
                   REJECT_NAN_FLAG + ": document.getElementById('" + 
                       REJECT_NAN_FLAG + "').checked" +
                   "};\n" +
                "  let html = 'unknown error';\n" +
                "  try {\n" +
                "    const response = await fetch('convert', {\n" +
                "      headers: {\n" +
                "        'Content-Type': '" + JSON_CONTENT_TYPE + "'\n" +
                "      },\n" +
                "      method: 'POST',\n" +
                "      body: JSON.stringify(jsonObject)\n" +
                "    });\n" +
                "    if (response.ok) {\n" +
                "      const jsonResult = await response.json();\n" +
                "      html = jsonResult." + ERROR + 
                    "? '<span style=\"color:red;font-weight:bold\">' + " +
                    "jsonResult." + ERROR + " + '</span>' : jsonResult." + CBOR_OUT + ";\n" +
                "    }\n" +
                "  } catch (e) {\n" +
                "    html = '<span style=\"color:red;font-weight:bold\">' + e + '</span>';\n" +
                "  }\n" +
                "  document.getElementById('" + CBOR_OUT + "').children[1].innerHTML = html;\n" +
                "}\n");

        StringBuilder html = new StringBuilder(
                "<div class='header'>CBOR Conversion Utility</div>" +
                "<div style='padding-top:15pt'>" + HomeServlet.SUPPORTED_CBOR + "</div>")
            .append(HTML.fancyText(
                        true,
                        CBOR_IN,
                        10,
                        "# CBOR sample, here expressed in Diagnostic Notation\n" +
                        "{\n  1: \"next\nline\",\n  2: [5.960465188081798e-8, " +
                        "0b100_000000001, b64'oQVkZGF0YQ', true, 0(\"" +
                        ISODateTime.encode(new GregorianCalendar(), 
                                           ISODateTime.UTC_NO_SUBSECONDS) +
                        "\")]\n}",
                        selector(SEL_IN, true) +
                          "Paste a CBOR object in the text box or try with the default"))
            .append(HTML.fancyBox(
                        CBOR_OUT,
                        "",
                        selector(SEL_OUT, false) + "Converted result using " + DETERMINISTIC_LINK))           
            .append(
                "<div style='display:flex;justify-content:center'>" +
                "<div class='stdbtn' onclick=\"delayedConvert()\">" +
                "Convert!" +
                "</div>" +
                "</div>" +
                "<div>&nbsp;</div>");
        HTML.standardPage(response, js.toString(), html);
    }
}

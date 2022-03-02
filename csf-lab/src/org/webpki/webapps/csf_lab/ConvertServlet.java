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

import javax.servlet.ServletException;
import javax.servlet.ServletOutputStream;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.cbor.CBORObject;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;
import org.webpki.util.HexaDecimal;

import org.webpki.webutil.ServletUtil;

public class ConvertServlet extends CoreRequestServlet {

    private static final long serialVersionUID = 1L;
    
    static final String CBOR_IN     = "cborin";
    static final String CBOR_OUT    = "cborout";
    static final String ERROR       = "error";
    
    static final String SEL_IN      = "selin";
    static final String SEL_OUT     = "selout";
    
    static final String DIAG        = "diag";
    static final String HEXA        = "hexa";
    static final String CSTYLE      = "cstyle";
    static final String B64U        = "b64u";
    
    static final String HTTP_PRAGMA              = "Pragma";
    static final String HTTP_EXPIRES             = "Expires";
    static final String HTTP_ACCEPT_HEADER       = "Accept";
    static final String HTTP_CONTENT_TYPE_HEADER = "Content-Type";

    static final String JSON_CONTENT_TYPE        = "application/json";
    
    String selector(String name, boolean primary) {
        return
            "<table style='margin-bottom:0.3em;border-spacing:0'>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + DIAG + "'" + (primary ? " checked" : "") + 
              "></td><td>Diagnostic notation</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + HEXA + "'" + (primary ? "" : " checked") +
            "></td><td>Hexadecimal notation" + (primary ? " (including possible #-comments)" 
                                                        : "") + "</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + CSTYLE + "'></td><td><code>0xhh, 0xhh...</code> notation</td></tr>" +
            "<tr><td><input type='radio' name='" + name + "' " +
            "value='" + B64U + "'></td><td>Base64Url notation</td></tr>" +
            "</table>";
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

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        JSONObjectWriter jsonResponse = new JSONObjectWriter();
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().equals("application/json")) {
                throw new IOException("Unexpected MIME type:" + request.getContentType());
            }
            JSONObjectReader parsedJson = JSONParser.parse(ServletUtil.getData(request));
            String inData = parsedJson.getString(CBOR_IN);
            CBORObject cbor;
            switch (parsedJson.getString(SEL_IN)) {
                case DIAG:
                    cbor = CBORObject.decode(CBORDiagnosticParser.parse(inData).encode());
                    break;
    
                case CSTYLE:
                    inData = inData.toLowerCase().replace("0x", "").replace(',', ' ');
                case HEXA:
                    cbor = hexDecodedCbor(inData);
                    break;
    
                default:
                    cbor = CBORObject.decode(Base64URL.decode(inData));
                    break;
            }
            String outData;
            switch (parsedJson.getString(SEL_OUT)) {
                case DIAG:
                    outData = HTML.encode(cbor.toString()).replace("\n", "<br>")
                                                          .replace(" ","&nbsp;");
                    break;
    
                case HEXA:
                    outData = HexaDecimal.encode(cbor.encode());
                    break;
                    
                case CSTYLE:
                    outData = HexaDecimal.encode(cbor.encode());
                    StringBuilder cstyle = new StringBuilder();
                    for (int i = 0; i < outData.length(); ) {
                    if (i > 0) {
                        cstyle.append(", ");
                    }
                    cstyle.append("0x").append(outData.charAt(i++)).append(outData.charAt(i++));
                    }
                    outData = cstyle.toString();
                    break;
    
                default:
                    outData = Base64URL.encode(cbor.encode());
                    break;
            }
            jsonResponse.setString(CBOR_OUT, outData);
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
                   SEL_OUT + ": getRadioValue('" + SEL_OUT + "')" +
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
                "<div style='padding-top:15pt'>" + HomeServlet.SUPPORTED_CBOR + "</div>" +
                "<div style='padding-top:0.5em'>Note that hexadecimal and base64url encoded data must use " +
                "<i>deterministic representation</i>.</div>")
            .append(HTML.fancyText(
                        true,
                        CBOR_IN,
                        10, 
                        "{\n  5: \"data\"\n}",
                        selector(SEL_IN, true) +
                          "Paste a CBOR object in the text box or try with the default"))
            .append(HTML.fancyBox(
                        CBOR_OUT,
                        "",
                        selector(SEL_OUT, false) + "Converted result"))           
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

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
package org.webpki.webapps.json.jws;

import java.io.IOException;

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

import org.webpki.webutil.ServletUtil;

public class JavaScriptSignatureServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(JavaScriptSignatureServlet.class
            .getName());

    static void error(HttpServletResponse response, String error_message)
            throws IOException, ServletException {
        HTML.errorPage(response, error_message);
    }

    void showSignature(HttpServletRequest request,
            HttpServletResponse response, byte[] signed_json)
            throws IOException, ServletException {
        JSONObjectReader parsed_json = JSONParser.parse(signed_json);
        HTML.printResultPage(
                response,
                "<table>"
                        + "<tr><td align=\"center\" style=\"font-weight:bolder;font-size:10pt;font-family:arial,verdana\">Signed JavaScript Object<br>&nbsp;</td></tr>"
                        + "<tr><td align=\"left\">"
                        + HTML.fancyBox(
                                "verify",
                                new String(
                                        new JSONObjectWriter(parsed_json)
                                                .serializeToBytes(JSONOutputFormats.PRETTY_JS_NATIVE),
                                        "UTF-8").replace("\n", "<br>").replace("  ", "&nbsp;&nbsp;&nbsp;&nbsp;"))
                        + "</td></tr>"
                        + "</table>");
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        byte[] data = null;
        if (request.getContentType().startsWith(
                "application/x-www-form-urlencoded")) {
            data = Base64URL.decode(request.getParameter(RequestServlet.JWS_ARGUMENT));
        } else {
            if (!request.getContentType().startsWith("application/json")) {
                error(response, "Request didn't have the proper mime-type: "
                        + request.getContentType());
                return;
            }
            data = ServletUtil.getData(request);
        }
        try {
            showSignature(request, response, data);
        } catch (IOException e) {
            HTML.errorPage(response, e.getMessage());
            return;
        }
    }

}

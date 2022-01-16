/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.json.JSONOutputFormats;
import org.webpki.json.JSONParser;

public class JavaScriptSignatureServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    static Logger logger = Logger.getLogger(JavaScriptSignatureServlet.class.getName());

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        try {
            request.setCharacterEncoding("utf-8");
            if (!request.getContentType().startsWith("application/x-www-form-urlencoded")) {
                throw new IOException("Unexpected MIME type: " + request.getContentType());
            }
            String htmlSafe = HTML.encode(
                JSONParser.parse(CreateServlet.getParameter(request, 
                                                            ValidateServlet.JSF_OBJECT))
                    .serializeToString(JSONOutputFormats.PRETTY_JS_NATIVE))
                        .replace("\n", "<br>")
                        .replace("  ", "&nbsp;&nbsp;&nbsp;&nbsp;");
            HTML.standardPage(
                response,
                null, 
                new StringBuilder("<div class='header'>Signatures in JavaScript Notation</div>")
                    .append(HTML.fancyBox("verify",
                                          htmlSafe,
                                          "Signed JavaScript object"))
                    .append("<div style='padding-top:20pt'>Note that the signature above is " +
                            "not verified.  The only difference between " +
                            "the JavaScript notation and &quot;true&quot; JSON is the removal " +
                            "of the (usually redundant) quote characters around " +
                            "property names.  Names that interfere with JavaScript naming " +
                            "conventions for variables like '5' or 'my.prop' will though " +
                            "be quoted.</div>" +
                            "<div style='padding-top:5pt'>Since the JavaScript " +
                            "<code>JSON.stringify()</code> " +
                            "method restores the 'true' JSON format, the two notations " +
                            "are fully interoperable.</div>"));
        } catch (IOException e) {
            HTML.errorPage(response, e);
        }
    }
}

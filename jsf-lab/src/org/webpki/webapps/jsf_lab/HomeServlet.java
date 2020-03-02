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
package org.webpki.webapps.jsf_lab;

import java.io.IOException;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class=\"header\">JSON Signature Format (JSF)</div>" +
            "<div style=\"padding-top:15pt\">This site permits testing and debugging systems utilizing a " +
            "scheme for clear text JSON signatures tentatively targeted for " +
            "IETF standardization.  For detailed technical information and " +
            "open source code, click on the JSF logotype.</div>" +
            "<div style=\"display:flex;justify-content:center\"><table>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='create'\" " +
            "title=\"Create JSF signatures\">" +
            "Create JSF Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='validate'\" " +
            "title=\"Validate JSF signatures\">" +
            "Validate JSF Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class=\"multibtn\" " +
            "onclick=\"document.location.href='webcrypto'\" " +
            "title=\"&quot;Experimental&quot; - WebCrypto\">" +
            "&quot;Experimental&quot; - WebCrypto" +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class=\"sitefooter\">Privacy/security notice: No user provided data is " +
            "ever stored or logged on the server; it only processes the data and returns the " +
            "result.</div>"));
    }
}

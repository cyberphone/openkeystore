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

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public class HomeServlet extends CoreRequestServlet {

    private static final long serialVersionUID = 1L;
    
    static final String SUPPORTED_CBOR = "This implementation supports the " +
            "[<a href='https://www.ietf.org/archive/id/draft-rundgren-cbor-core-11.html' " +
            "target='_blank' title='cbor'>CBOR::Core</a>] primitives (" +
            "<code>tstr</code>, <code>bstr</code>, " +
            "<code>int</code>, <code>bigint</code>, " +
            "<code>float</code>, " +
            "<code>bool</code>, <code>null</code>, " +
            "<code><i>tagged&nbsp;data</i></code>, and " +
            "<code><i>simple&nbsp;values</i></code>).";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {

        HTML.standardPage(response, null, new StringBuilder(
            "<div class='header'>CBOR Signature Format (CSF)</div>" +
            "<div style='padding-top:15pt'>This service permits testing and " +
            "debugging CBOR " +
            "[<a href='https://www.rfc-editor.org/rfc/rfc8949.html' " +
            "target='_blank' title='cbor'>RFC&nbsp;8949</a>] based systems " +
            "using digital signatures. Unlike COSE " +
            "[<a href='https://datatracker.ietf.org/doc/html/rfc8152' " +
            "target='_blank' title='cose'>RFC&nbsp;8152</a>], " +
            "CSF utilizes " + DETERMINISTIC_LINK + " enabling signatures " +
            "to become a part of the application data, rather than embedding " +
            "such data in signatures.  For detailed technical information " +
            "click on the CSF logotype.</div>" +
            "<div style='margin-top:0.7em'>" + SUPPORTED_CBOR + "</div>" +
            "<div style='display:flex;justify-content:center'><table>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='create'\" " +
            "title='Create CSF signatures'>" +
            "Create CSF Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='validate'\" " +
            "title='Validate CSF signatures'>" +
            "Validate CSF Signatures" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='convert'\" " +
            "title='CBOR Conversion Utility'>" +
            "CBOR Conversion Utility" +
            "</div></td></tr>" +
            "<tr><td><div class='multibtn' " +
            "onclick=\"document.location.href='cosekey'\" " +
            "title='Key Conversion Utility'>" +
            "Key Conversion Utility" +
            "</div></td></tr>" +
            "</table></div>" +
            "<div class='sitefooter'>Privacy/security notice: No user provided data is " +
            "ever stored or logged on the server; it only processes the data and returns the " +
            "result.</div>"));
    }
}

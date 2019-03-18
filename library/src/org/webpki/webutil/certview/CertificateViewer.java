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
package org.webpki.webutil.certview;

import java.io.IOException;

import java.util.GregorianCalendar;
import java.util.TimeZone;
import java.text.SimpleDateFormat;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.DebugFormatter;
import org.webpki.util.ArrayUtil;
import org.webpki.util.HTMLEncoder;
import org.webpki.util.HTMLHeader;
import org.webpki.util.Base64;

import org.webpki.webutil.DefaultHTML;

import org.webpki.crypto.CertificateInfo;


@SuppressWarnings("serial")
public abstract class CertificateViewer extends HttpServlet {

    private String niceDate(GregorianCalendar dateTime) {
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MMM-dd HH:mm:ss z");
        sdf.setTimeZone(TimeZone.getTimeZone("UTC"));
        return sdf.format(dateTime.getTime());
    }


    private void add(StringBuilder s, String header, String data, String color) {
        s.append("<tr><td colspan=\"3\" height=\"8\"></td></tr><tr valign=\"top\" bgcolor=\"").
                append(color).
                append("\"><td><b>").
                append(header).
                append("&nbsp;&nbsp;</b></td><td>").
                append(data).
                append("</td><td>&nbsp;</td></tr>");
    }


    private void add(StringBuilder s, String header, String data) {
        add(s, header, data, "#e0e0e8");
    }


    private void insertURI(StringBuilder s, String uri) {
        s.append("<a href=\"").append(uri).append("\" target=\"_blank\" " +
                "style=\"font-weight:normal;font-size:8pt;font-family:verdana,arial\">").
                append(uri).
                append("</a>");
    }


    private void printURIs(StringBuilder s, String header, String[] inuris) throws IOException {
        if (inuris != null) {
            StringBuilder uris = new StringBuilder();
            boolean break_it = false;
            for (String uri : inuris) {
                boolean http = uri.startsWith("http") && !header.startsWith("OCSP");
                if (break_it) {
                    uris.append(http ? "<br>" : ", ");
                } else {
                    break_it = true;
                }
                if (http) {
                    insertURI(uris, uri);
                } else {
                    uris.append("<nobr>").append(uri).append("</nobr>");
                }
            }
            add(s, header, uris.toString());
        }
    }


    public abstract CertificateInfo getCertificateInfo(HttpServletRequest request) throws IOException, ServletException;


    public String getDocumentTitle() throws IOException {
        return "Certificate Properties";
    }


    public boolean trustModeWanted() throws IOException {
        return false;
    }


    public static String getWindowOpenJS(String url) {
        return "window.open (" + url + ",'_blank','height=600,width=600,resizable=yes,scrollbars=yes,toolbar=no,menubar=yes,location=no,status=no')";
    }


    public StringBuilder createHTMLHeader() throws IOException {
        return HTMLHeader.createHTMLHeader(false, true, getDocumentTitle(), null);
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        boolean no_session = request.getSession(false) == null;
        CertificateInfo ci = getCertificateInfo(request);
        if (ci == null) {
            DefaultHTML.setErrorHTML(response,
                    "No certificate data found." +
                            (no_session ? "<br>(this is probably due the fact that the session has timed-out)" : ""),
                    true);
            return;
        }
        StringBuilder s = createHTMLHeader().append(
                "<body><table cellpadding=\"2\" cellspacing=\"0\">").
                append("<tr><td colspan=\"3\" class=\"headline\">").
                append(getDocumentTitle()).
                append("</td></tr><tr><td height=\"10\" colspan=\"3\"></td></tr>");
        add(s, "Issuer", HTMLEncoder.encode(ci.getIssuer()));
        add(s, "Serial&nbsp;number", ci.getSerialNumber() + " (0x" + ci.getSerialNumberInHex() + ")");
        add(s, "Subject", HTMLEncoder.encode(ci.getSubject()));
        add(s, "Valid&nbsp;from", niceDate(ci.getNotBeforeDate()));
        add(s, "Valid&nbsp;to", niceDate(ci.getNotAfterDate()));
        String bc = ci.getBasicConstraints();
        if (bc != null) {
            add(s, "Basic&nbsp;constraints", bc);
        }
        printURIs(s, "Key&nbsp;usage", ci.getKeyUsages());
        printURIs(s, "Extended&nbsp;key&nbsp;usage", ci.getExtendedKeyUsage());
        printURIs(s, "Policy&nbsp;OIDs", ci.getPolicyOIDs());
        printURIs(s, "AIA&nbsp;CA&nbsp;issuers", ci.getAIACAIssuers());
        printURIs(s, "OCSP&nbsp;reponders", ci.getAIAOCSPResponders());
        add(s, "SHA1&nbsp;fingerprint", ArrayUtil.toHexString(ci.getCertificateHash(), 0, -1, true, ' '));
        add(s, "Public&nbsp;key", ci.getPublicKeyAlgorithm() + " (" + ci.getPublicKeySize() + " bits)" +
                "<pre style=\"margin-top:5px;margin-bottom:0px\">" +
                DebugFormatter.getHexDebugData(ci.getPublicKeyData(), -16) + "</pre>");
        if (trustModeWanted()) {
            add(s,
                    "Trust", ci.isTrusted() ?
                            "This certificate is issued by a CA trusted by the application" :
                            "<font color=\"red\">This certificate is issued by an unknown CA</font>",
                    "#ffffb0");
        }
        s.append("<tr><td colspan=\"3\" height=\"20\"></td></tr><tr><td colspan=\"3\">" +
                "<button type=\"button\" onclick=\"document.shoot.submit ()\"" +
                ">Download certificate...</button></td></tr>" +
                "</table><br><form name=\"shoot\" action=\"").
                append(request.getRequestURL().toString()).
                append("\" method=\"POST\"><input type=\"hidden\" name=\"certblob\" value=\"").
                append(new Base64().getBase64StringFromBinary(ci.getCertificateBlob())).
                append("\"></form></body></html>");
        DefaultHTML.setHTMLMode(response);
        response.getOutputStream().print(s.toString());
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String ad = request.getParameter("certblob");
        if (ad == null) {
            throw new IOException("Missing request data");
        }
        byte data[] = new Base64().getBinaryFromBase64String(ad);
        response.setContentType("application/pkix-cert");
        response.setHeader("Content-Disposition", "inline; filename=certificate.cer");
        response.getOutputStream().write(data);
    }

}

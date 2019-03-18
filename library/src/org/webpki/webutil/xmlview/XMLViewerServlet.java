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
package org.webpki.webutil.xmlview;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import org.webpki.util.Base64;
import org.webpki.tools.XML2HTMLPrinter;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public abstract class XMLViewerServlet extends HttpServlet {

    static final String base = "font-weight: normal;font-family: arial, helvetica, sans-serif;font-size: 10pt";

    static final String bold = "font-weight: bold;font-family: arial, helvetica, sans-serif;font-size: 10pt; color:" +
            "blue;text-decoration: none";

    static final String thin = base + "; color:" + XML2HTMLPrinter.NSVALUE_COLOR + ";text-decoration: none";

    private void bug(String msg, HttpServletResponse response) throws IOException, ServletException {
        setHTMLMode(response);
        StringBuilder s = new StringBuilder();
        s.append("<html><head><title>Error</title></head>" +
                "<body style=\"" + base + "\">" + msg + "</body></html>");
        response.getOutputStream().print(s.toString());
    }


    private void setHTMLMode(HttpServletResponse response) {
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", -1);
    }


    protected String getSchemaViewerName() {
        return "SchemaViewer";
    }


    protected String getXMLViewerName() {
        return "XMLViewer";
    }


    protected abstract byte[] getData(String what, HttpServletRequest request) throws IOException, ServletException;


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if (request.getSession(false) == null) {
            bug("Session time-out.  In case you are using MSIE this may be due to a bug in MSIE " +
                    "requiring you to close <b>all</b> MSIE windows and start over", response);
            return;
        }
        String M = request.getParameter("M");
        if (M == null) {
            bug("M param missing", response);
            return;
        }
        String S = request.getParameter("S");
        if (S == null) {
            bug("S param missing", response);
            return;
        }
        String F = request.getParameter("F");
        if (F == null) {
            bug("F param missing", response);
            return;
        }
        String baseurl = ServletUtil.getContextURL(request);
        byte[] data = getData(S, request);

        setHTMLMode(response);
        StringBuilder s = new StringBuilder();
        s.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
                "<html><head>" +
                "<title>XML Object: " + M + "</title><style type=\"text/css\">\n" +
                "a.g:link {" + thin + "}\n" +
                "a.g:hover {" + thin + "}\n" +
                "a.g:visited {" + thin + "}\n" +
                "a.g:active {" + thin + "}\n" +
                "a:link {" + bold + "}\n" +
                "a:hover {" + bold + "}\n" +
                "a:visited {" + bold + "}\n" +
                "a:active {" + bold + "}\n" +
                "</style><script language=\"javascript\">\n" +
                "function viewxml (url)\n" +
                "{\n" +
                "  window.open (url,'_blank','resizable=yes,scrollbars=yes,toolbar=no,menubar=yes,location=no,status=no');\n" +
                "}\n" +
                "</script></head>" +
                "<body style=\"word-wrap:break-word;" + base + "\"><b>" + M + "</b><p>" +
                "<form name=\"shoot\" action=\"" + baseurl + "/" + getXMLViewerName() + "/" + F +
                "\" method=\"POST\" target=\"_blank\">" +
                "<input type=\"hidden\" name=\"data\" value=\"" +
                new Base64(false).getBase64StringFromBinary(data) +
                "\"></form>" +
                "<a href=\"javascript:document.shoot.submit ()\">Click here to get raw XML</a><p>").
                append((getSchemaViewerName() == null ? "" : "Click on XML name-space URIs to view the associated schemas<p><hr><p>")).
                append("<div style=\"" + base + ";width: 650px\">").
                append((getSchemaViewerName() == null ?
                        XML2HTMLPrinter.convert(new String(data, "UTF-8")) :
                        XML2HTMLPrinter.convert(new String(data, "UTF-8"),
                                "<a class=\"g\" href=\"javascript:viewxml('" + baseurl + "/" +
                                        getSchemaViewerName() + "/" + XML2HTMLPrinter.URL_HEX_LINK + "?HEAD=TRUE')\">"))).
                append("</div></body></html>");

        response.getOutputStream().print(s.toString());
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String udata = request.getParameter("data");
        if (udata == null) {
            bug("<b>Error: </b>udata is incorrect", response);
            return;
        }
        byte[] data = new Base64().getBinaryFromBase64String(udata);
        response.setContentType("text/xml");
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream().write(data);
    }

}

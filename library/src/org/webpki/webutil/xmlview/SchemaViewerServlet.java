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

import org.webpki.util.DebugFormatter;
import org.webpki.util.Base64;
import org.webpki.tools.XSD2HTMLPrinter;

import org.webpki.webutil.ServletUtil;


@SuppressWarnings("serial")
public abstract class SchemaViewerServlet extends HttpServlet {

    public class ReturnValue {
        byte[] data;
        String file;

        public ReturnValue(byte[] data, String file) {
            this.data = data;
            this.file = file;
        }
    }

    static final String base = "font-weight: normal;font-family: arial, helvetica, sans-serif;font-size: 10pt";

    static final String bold = "font-weight: bold;font-family: arial, helvetica, sans-serif;font-size: 10pt; color:" +
            "blue;text-decoration: none";

    static final String thin = base + "; color:" + XSD2HTMLPrinter.NSVALUE_COLOR + ";text-decoration: none";

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


    protected abstract ReturnValue getData(String url, HttpServletRequest request) throws IOException, ServletException;


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String path = request.getPathInfo();
        if (path == null || path.length() < 5) {
            bug("bad url", response);
            return;
        }
        String url = new String(DebugFormatter.getByteArrayFromHex(path.substring(1)), "UTF-8");
        ReturnValue rv = getData(url, request);
        if (rv == null) {
            bug("No schema file available for <b>" + url + "</b>", response);
            return;
        }
        boolean head = request.getParameter("HEAD") != null;
        String baseurl = ServletUtil.getContextURL(request);
        setHTMLMode(response);
        StringBuilder s = new StringBuilder();
        s.append("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\">" +
                "<html><head>" +
                "<title>XML Schema: " + url + "</title><style type=\"text/css\">\n" +
                "a.g:link {" + thin + "}\n" +
                "a.g:hover {" + thin + "}\n" +
                "a.g:visited {" + thin + "}\n" +
                "a.g:active {" + thin + "}\n" +
                "a:link {" + bold + "}\n" +
                "a:hover {" + bold + "}\n" +
                "a:visited {" + bold + "}\n" +
                "a:active {" + bold + "}\n" +
                "</style>" +
                (head ? "<script type=\"text/javascript\">\n" +
                        "function viewxml (url)\n" +
                        "{\n" +
                        "  window.open (url,'_blank','resizable=yes,scrollbars=yes,toolbar=no,menubar=yes,location=no,status=no');\n" +
                        "}\n" +
                        "</script>" : "") +
                "</head><body style=\"color: #000000; background-color: #ffffff;" + base + "\">" +
                (head ? "<form name=\"shoot\" action=\"" + baseurl + "/" + getXMLViewerName() + "/" + rv.file +
                        "\" method=\"POST\" target=\"_blank\">" +
                        "<input type=\"hidden\" name=\"data\" value=\"" +
                        new Base64(false).getBase64StringFromBinary(rv.data) +
                        "\"></form>" +
                        "<a href=\"javascript:document.shoot.submit ()\">Click here to get raw XML</a><p>" +
                        "Click on XML name-space URIs to view the other schemas<p>" +
                        "<a href=\"" + baseurl + "/" + getSchemaViewerName() + "/" + DebugFormatter.getHexString(url.getBytes("UTF-8")) +
                        "\">Click here to get listing without a header</a> (suitable for printing)<p><hr><p>" : "") +
                XSD2HTMLPrinter.convert(new String(rv.data, "UTF-8"),
                        head ? "<a class=\"g\" href=\"javascript:viewxml('" + baseurl + "/" + getSchemaViewerName() +
                                "/" + XSD2HTMLPrinter.URL_HEX_LINK + "?HEAD=TRUE')\">" : null, !head) + "</body></html>");

        response.getOutputStream().print(s.toString());
    }

}

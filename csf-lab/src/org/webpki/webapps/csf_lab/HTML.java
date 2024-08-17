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

import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.UTF8;

public class HTML {

    static Logger logger = Logger.getLogger(HTML.class.getName());

    static final String HTML_INIT = "<!DOCTYPE html>" +
        "<html lang='en'><head><link rel='icon' href='webpkiorg.png' sizes='192x192'>" + 
        "<meta name='viewport' content='initial-scale=1.0'>" + 
        "<title>CBOR Signature Format (CSF)</title>" + 
        "<link rel='stylesheet' type='text/css' href='style.css'>";

    static String encode(String val) {
        if (val != null) {
            StringBuilder buf = new StringBuilder(val.length() + 8);
            char c;

            for (int i = 0; i < val.length(); i++) {
                c = val.charAt(i);
                switch (c) {
                case '<':
                    buf.append("&lt;");
                    break;
                case '>':
                    buf.append("&gt;");
                    break;
                case '&':
                    buf.append("&amp;");
                    break;
                case '\"':
                    buf.append("&#034;");
                    break;
                case '\'':
                    buf.append("&#039;");
                    break;
                default:
                    buf.append(c);
                    break;
                }
            }
            return buf.toString();
        } else {
            return new String("");
        }
    }

    static String getHTML(String javascript, String box) {
        StringBuilder html = new StringBuilder(HTML_INIT);
        if (javascript != null) {
            html.append("<script>").append(javascript)
                    .append("</script>");
        }
        html.append("</head><body>" +
            "<div style='display:flex;flex-wrap:wrap-reverse;justify-content:space-between'>" +
            "<div><img src='thelab.svg' " +
            "style='cursor:pointer;height:25pt;padding-bottom:10pt;margin-right:30pt'" +
            " onclick=\"document.location.href='home'\" title='Home of the lab...'></div>" +
            "<div style='display:flex;padding-bottom:10pt'>" +
            "<a href='https://cyberphone.github.io/javaapi/org/webpki/cbor/doc-files/signatures." +
            "html' target='_blank'><img src='csf.svg' " +
            "style='height:22pt' " +
            "title='CSF Specification'></a>" +
            "</div>" +
            "</div>")
         .append(box).append("</body></html>");
        return html.toString();
    }

    static void output(HttpServletResponse response, String html)
            throws IOException, ServletException {
        if (CSFService.logging) {
            logger.info(html);
        }
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        response.getOutputStream().write(UTF8.encode(html));
    }

    static String getConditionalParameter(HttpServletRequest request,
            String name) {
        String value = request.getParameter(name);
        if (value == null) {
            return "";
        }
        return value;
    }
    
    public static String boxHeader(String id, String text, boolean visible) {
        return new StringBuilder("<div id='")
            .append(id)
            .append("' style='padding-top:10pt")
            .append(visible ? "" : ";display:none")
            .append("'>" +
               "<div style='padding-bottom:3pt'>" + text + ":</div>").toString();
    }

    public static String fancyBox(String id, String content, String header) {
        return boxHeader(id, header, true) +
            "<div class='staticbox'>" + 
                encode(content).replace("\n", "<br>").replace(" ", "&nbsp;") + 
             "</div></div>";
    }

    public static String fancyText(boolean visible,
                                   String id, 
                                   int rows, 
                                   String content,
                                   String header) {
        return boxHeader(id, header, visible) +
            "<textarea" +
            " rows='" + rows + "' maxlength='100000'" +
            " class='textbox' name='" + id + "'>" + 
            encode(content) +
            "</textarea></div>";
    }
    
    static void standardPage(HttpServletResponse response, 
                            String javaScript,
                            StringBuilder html) throws IOException, ServletException {
        HTML.output(response, HTML.getHTML(javaScript, html.toString()));
    }

    static String javaScript(String string) {
        StringBuilder html = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c == '\n') {
                html.append("\\n");
            } else {
                html.append(c);
            }
        }
        return html.toString();
    }

    public static void errorPage(HttpServletResponse response, Exception e)
            throws IOException, ServletException {
        StringBuilder error = new StringBuilder()
            .append(e.getMessage())
            .append("\n\n")
            .append(e.getClass().getName())
            .append(':');
        StackTraceElement[] st = e.getStackTrace();
        int length = st.length;
        if (length > 20) {
            length = 20;
        }
        for (int i = 0; i < length; i++) {
            String entry = st[i].toString();
            if (entry.contains(".HttpServlet")) {
                break;
            }
            error.append("\n  at " + entry);
        }
        standardPage(response,
                     null,
                     new StringBuilder(
            "<div class='header' style='color:red'>Something went wrong...</div>" +
            "<div><pre>")
        .append(encode(error.toString()))
        .append("</pre></div>"));
    }
}

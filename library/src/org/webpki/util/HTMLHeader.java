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
package org.webpki.util;

import java.io.IOException;

public class HTMLHeader {

    public static StringBuilder createHTMLHeader(boolean dialog_style,
                                                boolean autoscrollbars,
                                                String title,
                                                String java_script) throws IOException {
        StringBuilder s = new StringBuilder("<!DOCTYPE HTML PUBLIC \"-//W3C//DTD HTML 4.0//EN\"><html><head>");
        if (title != null) {
            s.append("<title>").append(title).append("</title>");
        }
        s.append("<style type=\"text/css\">html {overflow:").
                append(autoscrollbars ? "auto}" : "hidden}");

        if (dialog_style) {
            s.append("html, body {margin:0px;padding:0px;height:100%}");
        }
        s.append("body {font-size:8pt;color:#000000;font-family:verdana,arial;background-color:white");
        if (!dialog_style) {
            s.append(";margin:10px");
        }
        s.append("}h2 {font-weight:bold;font-size:12pt;color:#000000;font-family:arial,verdana,helvetica}" +
                "h3 {font-weight:bold;font-size:11pt;color:#000000;font-family:arial,verdana,helvetica}" +
                "a:link {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}" +
                "a:visited {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana;text-decoration:none}" +
                "a:active {font-weight:bold;font-size:8pt;color:blue;font-family:arial,verdana}" +
                "input {font-weight:normal; font-size:8pt;font-family:verdana,arial}" +
                "td {font-size:8pt;font-family:verdana,arial}" +
                ".smalltext {font-size:6pt;font-family:verdana,arial}" +
                "button {font-weight:normal;font-size:8pt;font-family:verdana,arial;padding-top:2px;padding-bottom:2px}" +
                ".headline {font-weight:bolder;font-size:11pt;font-family:arial,verdana}" +
                "</style>");
        if (java_script != null) {
            s.append("<script type=\"text/javascript\">\n").append(java_script).append("</script>");
        }
        return s.append("</head>");
    }

}


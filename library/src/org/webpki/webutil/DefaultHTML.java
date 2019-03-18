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
package org.webpki.webutil;

import java.io.IOException;

import org.webpki.util.HTMLEncoder;
import org.webpki.util.HTMLHeader;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletResponse;

public class DefaultHTML {

    private DefaultHTML() {
    }


    public static void setHTMLMode(HttpServletResponse response) {
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
    }

    public static void setErrorHTML(HttpServletResponse response, String message, boolean html) throws IOException, ServletException {
        setHTMLMode(response);

        StringBuilder s = HTMLHeader.createHTMLHeader(true, false, "Error", null).
                append("<body><table width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                        "<table><tr><td align=\"center\" class=\"headline\">Standard Error Report<br>&nbsp;</td></tr><tr><td align=\"left\">").
                append(html ? message : HTMLEncoder.encode(message)).append("</td></tr></table></td></tr></table></body></html>");

        response.getOutputStream().print(s.toString());
    }

}

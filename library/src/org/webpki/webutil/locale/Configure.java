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
package org.webpki.webutil.locale;

import java.io.IOException;
import java.io.File;
import java.io.FileFilter;

import javax.servlet.ServletException;
import javax.servlet.ServletContext;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.webutil.ServletUtil;


public class Configure extends LocalizationServlet {

    private static final long serialVersionUID = 1L;  // Keep the compiler quite...

    protected LocalizedStrings[] getStringConstants() {
        return null;  // NEVER
    }


    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        String locale = request.getParameter("LOCALE");
        if (locale != null) {
            ServletContext context = getServletContext();
            context.setAttribute(LOCALE_ATTRIBUTE, locale);
            context.setAttribute(LOCALEDATA_ATTRIBUTE, null);
        }
        doGet(request, response);
    }


    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        StringBuilder s = new StringBuilder();

        response.setContentType("text/html");
        response.setDateHeader("EXPIRES", 0);

        s.append("<html><head><title>Locale (Language) configuration</title>" +
                "<style>\n" +
                "BODY {font-size: 8pt; color: #000000; font-family: Verdana, Arial; background-color: #ffffff}\n" +
                "A:link {font-weight: bold; font-size: 8pt; color: blue; font-family: Arial; text-decoration: none}\n" +
                "A:visited {font-weight: bold; font-size: 8pt; color: blue; font-family: Arial; text-decoration: none}\n" +
                "A:active {font-weight: bold; font-size: 8pt; color: blue; font-family: Arial}\n" +
                "INPUT {font-weight: normal; font-size: 8pt; font-family: Verdana, Arial}\n" +
                "TD {font-size: 8pt; font-family: Verdana, Arial}\n" +
                ".smalltext {font-size: 6pt; font-family: Verdana, Arial}\n" +
                "BUTTON {font-weight: normal; font-size: 8pt; font-family: Verdana, Arial}\n" +
                ".headline {font-weight: bolder; font-size: 11pt; font-family: Verdana, Arial}\n" +
                "</style>\n</head><body><form name=\"shoot\" action=\"" + getServletName() + "\" method=\"POST\" target=\"_top\">" +
                "<table border=\"0\" cellpadding=\"0\" cellspacing=\"0\" width=\"100%\" height=\"100%\"><tr><td align=\"center\" valign=\"middle\">" +
                "<table cellpadding=\"0\" cellspacing=\"0\" border=0>" +
                "<tr><td align=\"center\" class=\"headline\">Define application language</td></tr>" +
                "<tr><td height=\"20\"><td></tr>" +
                "<tr><td align=\"center\"><table>");
        ServletContext context = getServletContext();
        FileFilter fileFilter = new FileFilter() {
            public boolean accept(File file) {
                return file.isDirectory();
            }
        };
        File dir = new File(context.getRealPath("/WEB-INF/locale"));
        File[] files = dir.listFiles(fileFilter);
        for (int i = 0; i < files.length; i++) {
            String locale = files[i].getName();
            String checked = locale.equals(getLocale(context)) ? "checked " : "";
            LocalizedStringsSchema lss = getLocalizationData(locale, context);
            s.append("<tr><td>" +
                    "<input type=\"radio\" name=\"LOCALE\" " + checked + "value=\"" +
                    locale + "\"></td><td>" + lss.getLanguage() + "</td></tr>");
        }

        s.append("</table></td></tr><tr><td height=\"20\"><td></tr>" +
                "<tr><td align=\"center\"><input type=\"submit\" value=\"Update\"></td></tr>" +
                " <tr><td height=\"20\"><td></tr><tr><td align=\"center\"><a href=\"" +
                ServletUtil.getContextURL(request) + "\">Go to application</a><td></tr>" +
                "</table></td></tr></table></form></body></html>");
        response.getWriter().print(s.toString());
    }

}

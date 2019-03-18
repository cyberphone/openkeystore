/*
 *  Copyright 2006-2014 WebPKI.org (http://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package com.example.es6numbers;


import java.io.FileInputStream;
import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


public class TestServlet extends HttpServlet {

  private static final long serialVersionUID = 1L;
  
    private static final String ATTR_START = "start";
    
    private static final String SESS_FIS = "fis";
    private static final String SESS_TST = "tst";
    private static final String SESS_REC = "rec";
    
    private static final int LINES_PER_TEST = 10000;

    private static final String HEADER = 
        "<!DOCTYPE html><html><head><meta charset=\"UTF-8\"><title>ES6 - Number Canonicalizer</title>"
        + "<style type=\"text/css\">"
        + "body {font-family:verdana}"
        + "th {width:150pt;background:lightgrey;font-family:verdana;font-size:10pt;font-weight:normal;padding:4pt}"
        + "td {font-family:verdana;font-size:10pt;font-weight:normal;padding:2pt}"
        + "</style></head>";

    static void output (HttpServletResponse response, StringBuilder html) throws IOException, ServletException {
        response.setContentType ("text/html; charset=utf-8");
        response.setHeader ("Pragma", "No-Cache");
        response.setDateHeader ("EXPIRES", 0);
        response.getOutputStream().write (html.append("</body></html>").toString().getBytes ("UTF-8"));
    }

    public void doGet (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        StringBuilder s = new StringBuilder(HEADER).append("<body>");
        s.append(
            "<form method=\"POST\">" +
            "<input type=\"hidden\" name=\"" + ATTR_START + "\" value=\"true\">" +
            "<input type=\"submit\" + value=\"Start!\">" +
            "</form>");
        output(response, s);
    }
    
    String getArgument (HttpServletRequest request, String param) throws IOException
      {
        String res = request.getParameter (param);
        if (res == null || (res = res.trim()).length() == 0)
          {
            throw new IOException ("Missing parameter: " + param);
          }
        return res;
      }

    public void doPost (HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException
      {
        StringBuilder s = new StringBuilder(HEADER);
        HttpSession session = request.getSession(false);
        String start = request.getParameter(ATTR_START); 
        FileInputStream fis = null;
        Integer tst = null;
        Integer rec = null;
        if (start != null) {
            if (Boolean.valueOf(start)) {
                fis = new FileInputStream(getServletContext().getInitParameter("testfile"));
                session = request.getSession(true);
                session.setAttribute(SESS_FIS, fis);
                tst = new Integer(1);
                session.setAttribute(SESS_TST, tst);
                rec = new Integer(0);
                session.setAttribute(SESS_REC, rec);
            } else if (session == null) {
                response.sendRedirect (request.getRequestURL ().toString ());
                return;
            } else {
                fis = (FileInputStream) session.getAttribute(SESS_FIS);
                tst = (Integer) session.getAttribute(SESS_TST);
                rec = (Integer) session.getAttribute(SESS_REC);
            }
            s.append(
                "<body onload=\"runTest()\">Test #")
                .append(tst)
                .append("<form name=\"shoot\" method=\"POST\">");
            int insertPosition = s.length();
            s.append(
                "</form>" +
                "<script type=\"text/javascript\">\n" +
                "function runTest() {\n" +
                "  var i = 0;\n" +
                "  while (i < values.length) {\n" +
                "    var v = values[i++];\n" +
                "    if (parseFloat(v).toString() != v) {\n" +
                "       alert('Failed on: ' + v);\n" + 
                "    }\n" +
                "  }\n" +
                "  document.forms.shoot.submit();\n" +
                "}\n" +
                "var values = [\n");
            int lineCount = LINES_PER_TEST;
            boolean nextLine = false;
            boolean done = false;
            while (lineCount-- > 0) {
                boolean comma = false;
                int c;
                while ((c = fis.read()) != -1) {
                    if (comma) {
                        if (c == '\n') {
                            s.append('\'');
                            break;
                        }
                        s.append((char)c);
                    } else if (c == ',') {
                        comma = true;
                        if (nextLine) {
                            s.append(",\n");
                        }
                        nextLine = true;
                        s.append('\'');
                        rec++;
                    }
                }
                if (c == -1) {
                    done = true;
                    break;
                }
            }
            session.setAttribute(SESS_REC, rec);
            if (done) {
                fis.close();
            } else {
                s.insert(insertPosition, "<input type=\"hidden\" name=\"" + ATTR_START + "\" value=\"false\">");
                tst++;
                session.setAttribute(SESS_FIS, fis);
                session.setAttribute(SESS_TST, tst);
            }
            s.append(
                "];\n</script>");
        } else {
            s.append("<body>Success!" + (session == null ? "" :
                "<br>Tests: " + (Integer) session.getAttribute(SESS_REC)));
        }
        output(response, s);
      }
  }

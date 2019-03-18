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
package org.webpki.securityproxy.extservice;

import java.io.IOException;

import java.util.Date;
import java.util.logging.Logger;

import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

/**
 * This is the external service status servlet.
 */
public class ServiceStatus extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static Logger logger = Logger.getLogger(ServiceStatus.class.getName());

    @Override
    public void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        response.setContentType("text/html; charset=utf-8");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        StringBuilder s = new StringBuilder("<html><head><meta http-equiv=\"refresh\" content=\"20\"></head><body>");
        if (Init.proxy_server.isReady()) {
            s.append("Proxy Client ID = ").append(Init.proxy_server.getProxyClientID()).append("<p>");
            s.append("Last Proxy Upload: ");
            int l = Init.uploads.size();
            if (l == 0) {
                s.append("UNKNOWN");
            } else {
                printElem(s, 0);
                for (int q = 1; q < l; q++) {
                    s.append("<br>Previous Proxy Upload: ");
                    printElem(s, q);
                }
            }
        } else {
            s.append("PROXY SERVER NOT READY");
        }
        response.getWriter().print(s.append("</body></html>").toString());
    }

    private void printElem(StringBuilder s, int index) {
        s.append(new Date(Init.uploads.elementAt(index).getTimeStamp()).toString());
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        throw new IOException("POST not implemented");
    }
}

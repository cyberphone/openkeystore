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
import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;

import org.webpki.securityproxy.common.SampleRequestObject;
import org.webpki.securityproxy.common.SampleResponseObject;

/**
 * This is the external service java-2-java variant.
 */
public class ExtJavaService extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static Logger logger = Logger.getLogger(ExtJavaService.class.getName());

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        SampleResponseObject sro = (SampleResponseObject) Init.proxy_server.processCall(new SampleRequestObject(new Double(request.getParameter("X")),
                new Double(request.getParameter("Y")),
                new Long(request.getParameter("WAIT"))));
        response.setContentType("text/plain");
        response.setHeader("Pragma", "No-Cache");
        response.setDateHeader("EXPIRES", 0);
        response.getWriter().print(sro.getHeader() + sro.getResult());
    }
}

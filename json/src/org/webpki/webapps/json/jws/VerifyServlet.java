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
package org.webpki.webapps.json.jws;

import java.io.IOException;

import javax.servlet.RequestDispatcher;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.webpki.util.Base64URL;

public class VerifyServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;


    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        HTML.verifyPage(response, request, JWSService.testSignature);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("UTF-8");
        String json = CreateServlet.getTextArea(request);

        RequestDispatcher rd = request.getRequestDispatcher("request?"
                + RequestServlet.JWS_ARGUMENT + "="
                + Base64URL.encode(json.getBytes("UTF-8")));
        rd.forward(request, response);
    }
}

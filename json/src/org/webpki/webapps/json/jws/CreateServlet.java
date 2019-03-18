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

import org.webpki.json.JSONObjectReader;
import org.webpki.json.JSONObjectWriter;
import org.webpki.json.JSONParser;

import org.webpki.util.Base64URL;

public class CreateServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    static final String KEY_TYPE     = "keytype";
    static final String JS_FLAG      = "js";
    static final String KEY_INLINING = "keyinline";

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        HTML.createPage(response, request);
    }

    static public String getTextArea(HttpServletRequest request)
            throws IOException {
        String string = request.getParameter(RequestServlet.JWS_ARGUMENT);
        if (string == null) {
            throw new IOException("Missing data for: "
                    + RequestServlet.JWS_ARGUMENT);
        }
        StringBuilder s = new StringBuilder();
        for (char c : string.toCharArray()) {
            if (c != '\r') {
                s.append(c);
            }
        }
        return s.toString();
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws IOException, ServletException {
        request.setCharacterEncoding("UTF-8");
        String json_object = getTextArea(request);
        GenerateSignature.ACTION action = GenerateSignature.ACTION.EC;
        boolean jsFlag = request.getParameter(JS_FLAG) != null;
        boolean keyInlining = request.getParameter(KEY_INLINING) != null;
        String key_type = request.getParameter(KEY_TYPE);
        for (GenerateSignature.ACTION a : GenerateSignature.ACTION.values()) {
            if (a.toString().equals(key_type)) {
                action = a;
                break;
            }
        }
        try {
            JSONObjectReader reader = JSONParser.parse(json_object);
            JSONObjectWriter writer = new JSONObjectWriter(reader);
            byte[] signed_json = new GenerateSignature(action, keyInlining)
                    .sign(writer);
            RequestDispatcher rd = request
                    .getRequestDispatcher((jsFlag ? "jssignature?" : "request?")
                            + RequestServlet.JWS_ARGUMENT
                            + "="
                            + Base64URL.encode(signed_json));
            rd.forward(request, response);
        } catch (IOException e) {
            HTML.errorPage(response, e.getMessage());
        }
    }
}

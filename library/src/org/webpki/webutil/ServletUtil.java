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
import java.io.DataInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.File;

import java.security.GeneralSecurityException;
import java.security.KeyStore;

import javax.servlet.ServletContext;
import javax.servlet.ServletInputStream;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

public class ServletUtil {

    private ServletUtil() {}

    private static String getServerURL(HttpServletRequest request, String context) {
        StringBuilder r = new StringBuilder(request.isSecure() ? "https://" : "http://");

        if (request.getHeader("host") == null) {
            r.append(request.getServerName());

            if (request.getServerPort() != (request.isSecure() ? 443 : 80)) {
                r.append(request.getServerPort());
            }
        } else {
            r.append(request.getHeader("host"));
        }

        r.append(context);

        return r.toString();
    }


    public static String getServerRootURL(HttpServletRequest request) {
        return getServerURL(request, "/");
    }


    public static String getContextURL(HttpServletRequest request) {
        return getServerURL(request, request.getContextPath());
    }


    public static byte[] getData(HttpServletRequest request) throws java.io.IOException {
        int n = request.getContentLength();
        ServletInputStream is = request.getInputStream();
        if (n >= 0) {
            byte[] data = new byte[n];
            new DataInputStream(is).readFully(data);
            return data;
        } else {
            byte[] t = new byte[10240];
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            while ((n = is.read(t)) != -1) {
                baos.write(t, 0, n);
            }
            return baos.toByteArray();
        }
    }


    public static String getCookie(HttpServletRequest request, String name) {
        Cookie[] c = request.getCookies();
        if (c != null) {
            for (int i = 0; i < c.length; i++) {
                if (c[i].getName().equals(name)) {
                    return c[i].getValue();
                }
            }
        }

        return null;
    }


    public static KeyStore getKeyStore(ServletContext context, String certsfile, String password)
            throws IOException, GeneralSecurityException {
        FileInputStream file = new FileInputStream(context.getRealPath(File.separator +
                                                                       "WEB-INF" +
                                                                       File.separator +
                                                                       "classes" +
                                                                       File.separator +
                                                                       certsfile));
        KeyStore ks = KeyStore.getInstance("JKS");
        ks.load(file, password.toCharArray());
        return ks;
    }


}

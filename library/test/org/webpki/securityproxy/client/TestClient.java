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
package org.webpki.securityproxy.client;

import java.util.Random;

import javax.servlet.http.HttpServletResponse;

import org.webpki.net.HTTPSWrapper;

/**
 * Security proxy test client.
 */
public class TestClient {
    public static void main(String[] argc) {
        if (argc.length != 1 && argc.length != 5) {
            System.out.println("URL [count wait serverwait debuf]\n" +
                    "  URL using standard setup: http://localhost:8080\n" +
                    "  count is 1 if not given\n" +
                    "  wait is given in millseconds\n" +
                    "  serverwait is introduced every 10:th call and given in millseconds\n" +
                    "  debug true | false");
            System.exit(3);
        }
        try {
            HTTPSWrapper wrapper = new HTTPSWrapper();
            Random random = new Random();
            long wait = 0;
            int max = 1;
            int server_wait = 0;
            boolean debug = true;
            if (argc.length > 1) {
                max = Integer.parseInt(argc[1]);
                wait = Long.parseLong(argc[2]);
                server_wait = Integer.parseInt(argc[3]);
                debug = new Boolean(argc[4]);
            }
            int count = 0;
            while (count++ < max) {
                double x = random.nextDouble() * 10;
                double y = random.nextDouble() * 10;
                wrapper.setHeader("Content-Type", "application/x-www-form-urlencoded");
                wrapper.makePostRequestUTF8(argc[0] + (count % 2 == 0 ? "/http" : "/java"), "X=" + x + "&Y=" + y + "&WAIT=" + server_wait);
                if (wrapper.getResponseCode() != HttpServletResponse.SC_OK) {
                    System.out.println("Failed: " + wrapper.getResponseMessage() + "\n" + wrapper.getDataUTF8());
                } else if (debug) {
                    System.out.println("Local[" + count + "] X=" + x + " Y=" + y + " " + wrapper.getDataUTF8());
                }
                Thread.sleep(wait);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

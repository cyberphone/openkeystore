/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

import java.util.logging.Logger;


import java.net.InetAddress;


public class DNSReverseLookup {

    static Logger logger = Logger.getLogger(DNSReverseLookup.class.getName());

    private DNSReverseLookup() {}

    static String getHostName(String ipAddress) throws IOException, InterruptedException {
        if (System.getProperty("os.name").startsWith("Windows")) {
            return InetAddress.getByName(ipAddress).getHostName();
        }
        // -- Linux --
        String hostName = ipAddress;
        ProcessBuilder processBuilder = new ProcessBuilder();
        processBuilder.command("bash", "-c", "dig -x " + ipAddress);
        Process process = processBuilder.start();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));

        String line;
        boolean answer = false;
        boolean success = false;
        while ((line = reader.readLine()) != null) {
            if (answer) {
                reader.close();
                int i = line.lastIndexOf('\t');
                if (i > 0) {
                    hostName = line.substring(++i);
                    if (hostName.endsWith(".")) {
                        hostName = hostName.substring(0, hostName.length() - 1);
                    }
                    success = true;
                }
                break;
            } else if (line.contains("ANSWER SECTION:")) {
                answer = true;
            }
        }
        if (process.waitFor() != 0) {
            logger.warning("dig did not shut down properly");
        } else if (!success) {
            logger.warning("dig didn't provide an answer");
        }
        return hostName;
    }
    
    public static void main(String[] argc) {
        try {
            System.out.println(getHostName(argc[0]));
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

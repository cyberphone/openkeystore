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

import java.util.Vector;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.securityproxy.ProxyServer;
import org.webpki.securityproxy.ServerUploadHandler;
import org.webpki.securityproxy.JavaUploadInterface;
import org.webpki.securityproxy.common.SampleUploadObject;


public class Init implements ServletContextListener, ServerUploadHandler {
    private static Logger logger = Logger.getLogger(Init.class.getName());

    static ProxyServer proxy_server;

    private static final int HISTORY = 20;

    static Vector<SampleUploadObject> uploads = new Vector<SampleUploadObject>();

    @Override
    public void contextInitialized(ServletContextEvent event) {
        proxy_server = ProxyServer.getInstance(event.getServletContext().getInitParameter(ProxyServer.PROXY_SERVICE_PROPERTY));
        proxy_server.addUploadEventHandler(this);
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void handleUploadedData(JavaUploadInterface upload_payload) {
        uploads.add(0, (SampleUploadObject) upload_payload);
        if (uploads.size() > HISTORY) {
            uploads.setSize(HISTORY);
        }
        logger.info("Uploaded data reached service");
    }
}

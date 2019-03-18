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
package org.webpki.securityproxy.localservice;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Properties;
import java.util.logging.Logger;

import org.webpki.securityproxy.JavaResponseInterface;
import org.webpki.securityproxy.ProxyClient;
import org.webpki.securityproxy.ClientRequestHandler;
import org.webpki.securityproxy.JavaRequestInterface;
import org.webpki.securityproxy.HTTPResponseWrapper;
import org.webpki.securityproxy.common.SampleRequestObject;
import org.webpki.securityproxy.common.SampleResponseObject;
import org.webpki.securityproxy.common.SampleUploadObject;

/**
 * Test service using the security proxy system.
 */
public class TestService implements ClientRequestHandler {
    private static Logger logger = Logger.getLogger(TestService.class.getCanonicalName());

    private static final String DEFAULT_PROPERTIES_RESOURCE = "securityproxy.properties";

    private static final String PROPERTY_PROXY_URL = "securityproxy.url";
    private static final String PROPERTY_MAX_WORKERS = "securityproxy.max-workers";
    private static final String PROPERTY_CYCLE_TIME = "securityproxy.cycle-time";
    private static final String PROPERTY_REQUEST_TIMEOUT = "securityproxy.request-timeout";
    private static final String PROPERTY_DEBUG = "securityproxy.debug";

    private static final String PROPERTY_TRUSTSTORE = "securityproxy.truststore";
    private static final String PROPERTY_STOREPASS = "securityproxy.storepass";

    private static final String PROPERTY_KEYSTORE = "securityproxy.keystore";
    private static final String PROPERTY_KEYPASS = "securityproxy.keypass";

    ProxyClient proxy_client = new ProxyClient();

    Properties properties;

    boolean debug;

    boolean has_certificates;

    X509Certificate[] server_certificates;

    int count;

    private String getPropertyStringUnconditional(String name) throws IOException {
        String value = properties.getProperty(name);
        if (value == null) {
            throw new IOException("Property: " + name + " missing");
        }
        return value;
    }

    private String getPropertyString(String name) throws IOException {
        return getPropertyStringUnconditional(name);
    }

    private int getPropertyInt(String name) throws IOException {
        return Integer.parseInt(getPropertyStringUnconditional(name));
    }

    private boolean getPropertyBoolean(String name) throws IOException {
        String flag = getPropertyStringUnconditional(name);
        if (flag.equals("true")) return true;
        if (flag.equals("false")) return false;
        throw new IOException("Boolean syntax error: " + name);
    }

    private double getRequest(JavaRequestInterface request_object) throws IOException {
        if (!has_certificates) {
            has_certificates = true;
            server_certificates = proxy_client.getServerCertificates();
            logger.info("Server Certificate: " + (server_certificates == null ? "NONE" : server_certificates[0].getSubjectX500Principal().getName()));
        }
        if (debug) {
            logger.info("Received a \"" + request_object.getClass().getSimpleName() + "\" request[" + ++count + "]");
        }
        SampleRequestObject sps = (SampleRequestObject) request_object;
        long server_wait = sps.getServerWait();
        if (server_wait != 0 && count % 9 == 0) {
            try {
                Thread.sleep(server_wait);
            } catch (InterruptedException e) {
                throw new IOException(e);
            }
        }
        return sps.getX() * sps.getY();
    }

    @Override
    public HTTPResponseWrapper handleHTTPResponseRequest(JavaRequestInterface request_object) throws IOException {
        return new HTTPResponseWrapper(("HTTP Result[" + count + "]=" + getRequest(request_object)).getBytes("UTF-8"), "text/plain");
    }

    @Override
    public JavaResponseInterface handleJavaResponseRequest(JavaRequestInterface request_object) throws IOException {
        return new SampleResponseObject("JAVA Result[" + count + "]=", getRequest(request_object));
    }

    public static void main(String[] args) {
        try {
            new TestService().start(args.length == 0 ? null : new FileInputStream(args[0]));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private synchronized void uploadData() throws IOException {
        logger.info("Uploaded Data");
        proxy_client.addUploadObject(new SampleUploadObject(new Date().getTime()));
    }

    private void start(InputStream is) throws IOException {
        ////////////////////////////////////////////////////////////////////////////////////////////
        // Property fetching
        ////////////////////////////////////////////////////////////////////////////////////////////
        if (is == null) {
            is = this.getClass().getResourceAsStream("/META-INF/" + DEFAULT_PROPERTIES_RESOURCE);
        }
        properties = new Properties();
        properties.load(is);
        StringBuilder s = new StringBuilder();
        for (String key : properties.stringPropertyNames()) {
            if (s.length() > 0) {
                s.append(", ");
            }
            s.append(key).append('=').append(properties.getProperty(key));
        }
        logger.info("Properties: " + s.toString());

        ////////////////////////////////////////////////////////////////////////////////////////////
        // Initialization
        ////////////////////////////////////////////////////////////////////////////////////////////
        if (properties.containsKey(PROPERTY_TRUSTSTORE)) {
            proxy_client.setTrustStore(getPropertyString(PROPERTY_TRUSTSTORE), getPropertyString(PROPERTY_STOREPASS));
        }
        if (properties.containsKey(PROPERTY_KEYSTORE)) {
            proxy_client.setKeyStore(getPropertyString(PROPERTY_KEYSTORE), getPropertyString(PROPERTY_KEYPASS));
        }
        proxy_client.initProxy(this,
                getPropertyString(PROPERTY_PROXY_URL),
                getPropertyInt(PROPERTY_MAX_WORKERS),
                getPropertyInt(PROPERTY_CYCLE_TIME),
                getPropertyInt(PROPERTY_REQUEST_TIMEOUT),
                debug = getPropertyBoolean(PROPERTY_DEBUG));

        ////////////////////////////////////////////////////////////////////////////////////////////
        // Main loop
        ////////////////////////////////////////////////////////////////////////////////////////////
        while (true) {
            try {
                Thread.sleep(200000L);
                uploadData();
            } catch (InterruptedException e) {
                System.out.println("Interrupted!");
                return;
            }
        }
    }

    @Override
    public void handleInitialization() throws IOException {
        logger.info("Got restart signal!");
        has_certificates = false;
        uploadData();
    }

}

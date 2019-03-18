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
package org.webpki.securityproxy;

import java.io.IOException;
import java.io.OutputStream;
import java.io.ByteArrayOutputStream;
import java.io.BufferedInputStream;

import java.util.Date;
import java.util.Vector;

import java.util.logging.Level;
import java.util.logging.Logger;

import java.net.HttpURLConnection;
import java.net.Socket;
import java.net.URL;
import java.net.Proxy;
import java.net.InetSocketAddress;
import java.net.InetAddress;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;

import org.webpki.crypto.KeyStoreReader;

/**
 * Security proxy local service (client).
 */
public class ProxyClient {
    private static Logger logger = Logger.getLogger(ProxyClient.class.getCanonicalName());

    private ClientRequestHandler request_handler;

    /**
     * Creates a dormant security proxy client.
     * Instantiated by an "Inner Service".
     *
     * @see #initProxy(ClientRequestHandler, String, int, int, int, boolean) initProxy(ClientRequestHandler, String, int, int, int, boolean)
     */
    public ProxyClient() {
    }

    private class ProxyChannel implements Runnable {
        ////////////////////////////////////
        // Instance variables
        ////////////////////////////////////
        long channel_id;

        InternalClientObject send_object;

        boolean hanging;

        boolean running = true;

        private void badReturn(String what) {
            if (running) {
                logger.severe(proxy_url + " [" + channel_id + "] returned: " + what);
            }
        }

        public void run() {
            int error_count = 0;
            if (debug) {
                logger.info(proxy_url + " [" + channel_id + "] started");
            }
            while (running) {
                boolean throwed_an_iox = true;
                HttpURLConnection conn = null;
                try {
                    /////////////////////////////////////////////////////////////////////////////////////
                    // This how the proxy client starts its work-day, by launching a call to
                    // the proxy server. Usually the call contains nothing but sometimes
                    // there is a response from the local service included. The very first call
                    // contains a "master reset" which clears any resuidal objects in the server
                    // which may be left after a network or client proxy error.
                    /////////////////////////////////////////////////////////////////////////////////////
                    conn = (proxy == null) ? (HttpURLConnection) new URL(proxy_url).openConnection() : (HttpURLConnection) new URL(proxy_url).openConnection(proxy);

                    if (socket_factory != null) {
                        ((HttpsURLConnection) conn).setSSLSocketFactory(socket_factory);
                    }

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Are we starting or restarting?
                    /////////////////////////////////////////////////////////////////////////////////////
                    boolean restarting = send_object == server_configuration;

                    /////////////////////////////////////////////////////////////////////////////////////
                    // If there is no request in progress, check for pending uploads
                    /////////////////////////////////////////////////////////////////////////////////////
                    if (send_object instanceof InternalIdleObject) {
                        synchronized (upload_objects) {
                            if (!upload_objects.isEmpty()) {
                                send_object = upload_objects.remove(0);
                                if (debug) {
                                    logger.info("Upload initiated on " + proxy_url + " [" + channel_id + "]");
                                }
                            }
                        }
                    }

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Add a time-stamp
                    /////////////////////////////////////////////////////////////////////////////////////
                    send_object.time_stamp = new Date().getTime();

                    /////////////////////////////////////////////////////////////////////////////////////
                    // The following timeout only occurs if there is some kind of network problem
                    /////////////////////////////////////////////////////////////////////////////////////
                    conn.setReadTimeout((cycle_time * 3) / 2 + 30000);

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Direct mode only please!
                    /////////////////////////////////////////////////////////////////////////////////////
                    conn.setInstanceFollowRedirects(false);

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Serialize the data object to send (Conf, Idle, Response)
                    /////////////////////////////////////////////////////////////////////////////////////
                    byte[] send_data = InternalObjectStream.writeObject(send_object);

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Write Serialized object
                    /////////////////////////////////////////////////////////////////////////////////////
                    conn.setDoOutput(true);
                    OutputStream ostream = conn.getOutputStream();
                    ostream.write(send_data);
                    ostream.flush();
                    ostream.close();

                    /////////////////////////////////////////////////////////////////////////////////////
                    // For HTTPS we try to get the server certificate
                    /////////////////////////////////////////////////////////////////////////////////////
                    if (socket_factory != null && server_certificates == null) {
                        setServerCertificates((X509Certificate[]) (((HttpsURLConnection) conn).getServerCertificates()));
                    }

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Set the default object for the next round
                    /////////////////////////////////////////////////////////////////////////////////////
                    send_object = idle_object;

                    /////////////////////////////////////////////////////////////////////////////////////
                    // This is where the proxy client spends most its time - Waiting for some action
                    /////////////////////////////////////////////////////////////////////////////////////
                    hanging = true;
                    BufferedInputStream istream = new BufferedInputStream(conn.getInputStream());
                    ByteArrayOutputStream out = new ByteArrayOutputStream();
                    byte[] temp = new byte[1024];
                    int len;
                    while ((len = istream.read(temp)) != -1) {
                        out.write(temp, 0, len);
                    }
                    byte[] data = out.toByteArray();
                    int status = conn.getResponseCode();
                    if (status != HttpURLConnection.HTTP_OK) {
                        throw new IOException("Bad HTTP return:" + status);
                    }
                    istream.close();
                    conn.disconnect();
                    hanging = false;

                    /////////////////////////////////////////////////////////////////////////////////////
                    // If we have just restarted we give the local service a sign
                    /////////////////////////////////////////////////////////////////////////////////////
                    if (restarting) {
                        request_handler.handleInitialization();
                    }
                    throwed_an_iox = false;

                    /////////////////////////////////////////////////////////////////////////////////////
                    // Take care of the return data if there is such
                    /////////////////////////////////////////////////////////////////////////////////////
                    if (data.length == 0) {
                        /////////////////////////////////////////////////////////////////////////////////////
                        // No request data. See if it is time to just die..
                        /////////////////////////////////////////////////////////////////////////////////////
                        if (upload_objects.isEmpty()) {
                            if (unneededProxy(channel_id)) {
                                if (debug) {
                                    logger.info(proxy_url + " [" + channel_id + "] was deleted");
                                }
                                return;
                            }
                        }
                        if (debug) {
                            logger.info(proxy_url + " [" + channel_id + "] continues");
                        }
                    } else {
                        /////////////////////////////////////////////////////////////////////////////////////
                        // We do have a request in progress. Check that we have enough workers in action
                        /////////////////////////////////////////////////////////////////////////////////////
                        checkForProxyDemand(false);

                        /////////////////////////////////////////////////////////////////////////////////////
                        // Read the request object
                        /////////////////////////////////////////////////////////////////////////////////////
                        InternalRequestObject request_object = (InternalRequestObject) InternalObjectStream.readObject(data, request_handler);

                        /////////////////////////////////////////////////////////////////////////////////////
                        // Now do the request/response to the local service.  Honor waiting uploads as well
                        /////////////////////////////////////////////////////////////////////////////////////
                        send_object = new InternalResponseObject(request_object.java_flag ?
                                new HTTPResponseWrapper(
                                        InternalObjectStream.writeObject(
                                                request_handler.handleJavaResponseRequest(request_object.proxy_request)
                                        ),
                                        "application/java"
                                )
                                :
                                request_handler.handleHTTPResponseRequest(request_object.proxy_request),
                                request_object.caller_id,
                                client_id,
                                !upload_objects.isEmpty());
                    }

                    /////////////////////////////////////////////////////////////////////////////////////
                    // A round without errors. Reset error counter
                    /////////////////////////////////////////////////////////////////////////////////////
                    error_count = 0;
                } catch (ClassNotFoundException cnfe) {
                    badReturn("Unexpected object!");
                } catch (IOException ioe) {
                    if (debug) {
                        logger.log(Level.SEVERE, proxy_url + " [" + channel_id + "] returned:", ioe);
                    } else {
                        badReturn(ioe.getMessage());
                    }
                    try {
                        if (throwed_an_iox && running) {
                            String err = conn.getResponseMessage();
                            if (err != null) {
                                logger.severe(err);
                            }
                        }
                    } catch (IOException ioe2) {
                    }
                    if (running) {
                        /////////////////////////////////////////////////////////////////////////////////////
                        // Kill and remove all proxy channels (threads)
                        /////////////////////////////////////////////////////////////////////////////////////
                        killProxy();
                        ++error_count;

                        /////////////////////////////////////////////////////////////////////////////////////
                        // This looks pretty bad so we try restarting...
                        /////////////////////////////////////////////////////////////////////////////////////
                        running = true;
                        send_object = server_configuration;
                        channels.add(this);
                        try {
                            int retry_timeout = (request_timeout * 3) / 2;
                            if (debug) {
                                logger.info(proxy_url + " [" + channel_id + "] resumes (after waiting " + retry_timeout / 1000 + "s) for a new try...");
                            }
                            Thread.sleep(retry_timeout);
                        } catch (InterruptedException ie) {
                        }
                    }
                }
                hanging = false;
            }
        }
    }

    ////////////////////////////////////
    // Configurables
    ////////////////////////////////////
    private String proxy_url;

    private Proxy proxy;

    private int max_workers;

    private int cycle_time;

    private int request_timeout;

    private boolean debug;

    private KeyStore proxy_service_truststore;
    private KeyStore proxy_service_keystore;
    private String proxy_service_key_password;
    private String proxy_service_key_alias;

    private SSLSocketFactory socket_factory;

    private X509Certificate[] server_certificates;

    ////////////////////////////////////
    // App-wide "globals"
    ////////////////////////////////////
    private long last_channel_id;

    private String client_id;

    private InternalServerConfiguration server_configuration;

    private InternalIdleObject idle_object;

    private Vector<ProxyChannel> channels = new Vector<ProxyChannel>();

    private Vector<InternalUploadObject> upload_objects = new Vector<InternalUploadObject>();

    private void prepareForSSL() {
        if (proxy_url.startsWith("https:") && (proxy_service_truststore != null || proxy_service_keystore != null)) {
            try {
                TrustManager[] trust_managers = null;
                KeyManager[] key_managers = null;
                if (proxy_service_keystore != null) {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(proxy_service_keystore, proxy_service_key_password.toCharArray());
                    key_managers = kmf.getKeyManagers();
                    if (proxy_service_key_alias != null) {
                        final X509KeyManager orig_key_manager = (X509KeyManager) key_managers[0];
                        key_managers = new KeyManager[]{new X509KeyManager() {

                            @Override
                            public String chooseClientAlias(String[] key_type, Principal[] issuers, Socket socket) {
                                return proxy_service_key_alias;
                            }

                            @Override
                            public String chooseServerAlias(String key_type, Principal[] issuers, Socket socket) {
                                return orig_key_manager.chooseServerAlias(key_type, issuers, socket);
                            }

                            @Override
                            public X509Certificate[] getCertificateChain(String alias) {
                                return orig_key_manager.getCertificateChain(alias);
                            }

                            @Override
                            public String[] getClientAliases(String key_type, Principal[] issuers) {
                                return orig_key_manager.getClientAliases(key_type, issuers);
                            }

                            @Override
                            public PrivateKey getPrivateKey(String alias) {
                                return orig_key_manager.getPrivateKey(alias);
                            }

                            @Override
                            public String[] getServerAliases(String key_type, Principal[] issuers) {
                                return orig_key_manager.getServerAliases(key_type, issuers);
                            }

                        }};
                    }
                }
                if (proxy_service_truststore != null) {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(proxy_service_truststore);
                    trust_managers = tmf.getTrustManagers();
                }
                SSLContext ssl_context = SSLContext.getInstance("TLS");
                ssl_context.init(key_managers, trust_managers, null);
                socket_factory = ssl_context.getSocketFactory();
            } catch (GeneralSecurityException gse) {
                logger.log(Level.SEVERE, "SSL setup issues", gse);
            }
        }
    }

    private static char hex(int i) {
        if (i < 10) {
            return (char) (i + 48);
        }
        return (char) (i + 55);
    }

    static String toHexString(byte indata[]) {
        StringBuilder res = new StringBuilder();
        int i = 0;
        while (i < indata.length) {
            int v = indata[i++] & 0xFF;
            res.append(hex(v / 16));
            res.append(hex(v % 16));
        }
        return res.toString();
    }

    private synchronized void spawnProxy() {
        ProxyChannel channel = new ProxyChannel();
        channel.channel_id = last_channel_id++;

        /////////////////////////////////////////////////////////////////////////////////////////
        // If it is the first channel - issue a master reset + configuration to the proxy server
        /////////////////////////////////////////////////////////////////////////////////////////
        if (channel.channel_id == 0) {
            byte[] cid = new byte[10];
            new SecureRandom().nextBytes(cid);
            client_id = toHexString(cid);

            server_configuration = new InternalServerConfiguration(cycle_time, request_timeout, client_id);
            idle_object = new InternalIdleObject(client_id);
            channel.send_object = server_configuration;
            logger.info("Proxy at " + proxy_url + " ID=" + client_id + " initiated");
        } else {
            channel.send_object = idle_object;
        }
        channels.add(channel);
        new Thread(channel).start();
    }

    private synchronized void checkForProxyDemand(boolean increase) {
        /////////////////////////////////////////////////////////////////////////////////////
        // Check that there is ample of free channels in order to keep up with requests
        /////////////////////////////////////////////////////////////////////////////////////
        if (channels.size() < max_workers) {
            /////////////////////////////////////////////////////////////////////////////////////
            // We have not yet reached the ceiling
            /////////////////////////////////////////////////////////////////////////////////////
            int q = 0;
            for (ProxyChannel channel : channels) {
                if (channel.hanging) // = Most likely to be idle
                {
                    q++;
                }
            }
            if (increase) {
                q -= 2;
            }

            /////////////////////////////////////////////////////////////////////////////////////
            // The margin checker
            /////////////////////////////////////////////////////////////////////////////////////
            if (q < 2 || q < (max_workers / 5)) {
                /////////////////////////////////////////////////////////////////////////////////////
                // We could use a helping hand here...
                /////////////////////////////////////////////////////////////////////////////////////
                spawnProxy();
            }
        }
    }

    private synchronized void setServerCertificates(X509Certificate[] certificates) {
        server_certificates = certificates;
    }

    private synchronized boolean unneededProxy(long test_channel_id) throws IOException {
        if (channels.size() == 1) {
            /////////////////////////////////////////////////////////////////////////////////////
            // We must at least have one living thread...
            /////////////////////////////////////////////////////////////////////////////////////
            return false;
        }

        /////////////////////////////////////////////////////////////////////////////////////
        // Ooops. We are probably redundant...
        /////////////////////////////////////////////////////////////////////////////////////
        int q = 0;
        for (ProxyChannel channel : channels) {
            if (channel.channel_id == test_channel_id) {
                channels.remove(q);
                return true;
            }
            q++;
        }
        throw new IOException("Internal error.  Missing channel_id: " + test_channel_id);
    }

    /**
     * For HTTPS we may need the server's TLS certificate path.
     *
     * @return X509Certificate[] or null (for non-TLS connections)
     */
    public synchronized X509Certificate[] getServerCertificates() {
        return server_certificates;
    }

    /**
     * For HTTPS use this method as an alternative to the global truststore.
     *
     * @param truststore_file JKS or PKCS #12 file-name
     * @param password        Truststore password
     * @throws IOException If something unexpected happens...
     */
    public void setTrustStore(String truststore_file, String password) throws IOException {
        checkOrder();
        proxy_service_truststore = KeyStoreReader.loadKeyStore(truststore_file, password);
    }

    /**
     * For HTTPS client certificate authentication.
     *
     * @param keystore Instantiated Java KeyStore
     * @param password Key password
     * @throws IOException If something unexpected happens...
     */
    public void setKeyStore(KeyStore keystore, String password) throws IOException {
        checkOrder();
        proxy_service_keystore = keystore;
        proxy_service_key_password = password;
    }

    /**
     * For HTTPS client certificate authentication.
     *
     * @param keystore_file JKS or PKCS #12 file-name
     * @param password      Key password
     * @throws IOException If something unexpected happens...
     */
    public void setKeyStore(String keystore_file, String password) throws IOException {
        checkOrder();
        proxy_service_keystore = KeyStoreReader.loadKeyStore(keystore_file, password);
        proxy_service_key_password = password;
    }

    /**
     * For HTTPS client certificate authentication.
     *
     * @param keyAlias Key alias
     * @throws IOException If something unexpected happens...
     */
    public void setKeyAlias(String keyAlias) throws IOException {
        checkOrder();
        proxy_service_key_alias = keyAlias;
    }

    /**
     * Sets HTTP web-proxy parameters. This method needs to be called for usage
     * of the security proxy scheme where local LAN rules require outbound HTTP
     * calls to through a web-proxy server.
     * <p>
     * Note: <i>The proxy scheme does currently not support web-proxy authentication.</i>
     *
     * @param address The host name or IP address of the web-proxy server.
     * @param port    The TCP port number to use.
     * @throws IOException If something unexpected happens...
     */
    public void setWebProxy(String address, int port) throws IOException {
        checkOrder();
        proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(InetAddress.getByName(address), port));
    }

    private void checkOrder() throws IOException {
        if (proxy_url != null) {
            throw new IOException("This method must be called before initProxy!");
        }
    }

    /**
     * Terminates and clears the proxy connection(s).
     * A well-behaved client service should call this before terminating.
     */
    public synchronized void killProxy() {
        while (!channels.isEmpty()) {
            ProxyChannel channel = channels.remove(0);
            channel.running = false;
            if (debug) {
                logger.info(proxy_url + " [" + channel.channel_id + "] was relased");
            }
        }
        upload_objects.clear();
    }

    /**
     * Sets proxy core parameters and initializes the proxy channel.
     * <p>
     *
     * @param handler         The proxy user's interface.
     * @param proxy_url       The URL to the proxy channel.
     * @param max_workers     The maximum number of parallel proxy channels to use.
     * @param cycle_time      The timeout in seconds for the HTTP &quot;waiting&quot; state.
     * @param request_timeout The timeout in seconds for external proxy calls.
     * @param debug           Defines if debug output is to be created or not.
     * @throws IOException If something unexpected happens...
     * @see #setTrustStore(String, String) setTrustStore(String, String)
     * @see #setKeyStore(String, String) setKeyStore(String, String)
     */
    public void initProxy(ClientRequestHandler handler,
                          String proxy_url,
                          int max_workers,
                          int cycle_time,
                          int request_timeout,
                          boolean debug) throws IOException {
        killProxy();
        last_channel_id = 0;
        this.request_handler = handler;
        this.proxy_url = proxy_url;
        this.max_workers = max_workers;
        this.cycle_time = cycle_time * 1000;
        this.request_timeout = request_timeout * 1000;
        this.debug = debug;
        prepareForSSL();
        spawnProxy();
    }

    /**
     * Put an object for upload in a queue.
     * MUST NOT be called before {@link #initProxy(ClientRequestHandler, String, int, int, int, boolean)}.
     *
     * @param upload_object a derived object
     * @throws IOException If something unexpected happens...
     */
    public void addUploadObject(JavaUploadInterface upload_object) throws IOException {
        if (request_handler == null) {
            throw new IOException("addUploadObject called before initProxy");
        }
        synchronized (upload_objects) {
            upload_objects.add(new InternalUploadObject(client_id, upload_object));
        }
        checkForProxyDemand(true);
    }
}

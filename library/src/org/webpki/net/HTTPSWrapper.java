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
package org.webpki.net;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintWriter;

import java.net.Proxy;
import java.net.InetSocketAddress;
import java.net.InetAddress;
import java.net.Authenticator;
import java.net.PasswordAuthentication;
import java.net.Socket;
import java.net.URL;
import java.net.HttpURLConnection;

import java.util.ArrayList;
import java.util.Date;
import java.util.Enumeration;
import java.util.HashSet;
import java.util.Set;
import java.util.Vector;
import java.util.List;
import java.util.Map;
import java.util.LinkedHashMap;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.Provider;
import java.security.Security;

import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;

import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509KeyManager;
import javax.net.ssl.X509TrustManager;
import javax.net.ssl.TrustManager;
import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.KeyStoreReader;

import org.webpki.util.ArrayUtil;

/**
 * The HTTPSWrapper class makes it possible to establish HTTP/HTTPS connections
 * to web servers and compose HTTP requests.                       <br><br>
 * <p>
 * When making HTTP requests, the wrapper class does the following:   <br>
 * - Sets up http connections to a web server.                        <br>
 * - Performs a GET or POST request to the server.                  <br>
 * - Receives the response from the Web Server.                       <br><br>
 * <p>
 * When making HTTPS requests, the wrapper class does the following:   <br>
 * - Initializes a trust store for verifying server certificates.      <br>
 * - Sets up https connections to an ssl enabled web server.           <br>
 * - Performs a GET or POST request to the server.                  <br>
 * - Configures the SSL client to allow:                   <br>&nbsp;&nbsp;&nbsp;
 * - Untrusted server certificates.                    <br>&nbsp;&nbsp;&nbsp;
 * - Server certificates with invalid validity period.<br>&nbsp;&nbsp;&nbsp;
 * - Server certificates which Common Name does not match the
 * server DNS name.<br>
 * - Receives the response from the Web Server.                     <br><br>
 * <p>
 * In addition to the above mentioned features, the wrapper class makes it
 * possible to set and get HTTP request_headers and use proxy (firewall) servers.      <br><br>
 * <p>
 * When posting data to a server, the default content-type is
 * application/x-www-form-urlencoded                                <br><br>
 * <p>
 * Code example how to use the HTTPSWrapper.                            <br><br>
 * <PRE>
    try {
        HTTPSWrapper wrap = new HTTPSWrapper ();
        // Allow untrusted server certificates.
        wrap.allowInvalidCert (true);
        // Set HTTP request header. Must be set before making the request.
        wrap.setHeader ("MyStuff", "IsGreat");
        // If not called, the wrapper will use the Trust Store
        // supplied with the JRE. Must be called before making the request.
        wrap.setTrustStore ("Path to my store", "passphrase");
        // Make the request.
        wrap.makeGetRequest ("https://www.example.com");
        // Read the server response as a byte array.
        byte[] data = wrap.getData ();
    }
</PRE>
 */
public class HTTPSWrapper {
    private HttpURLConnection conn;
    private Proxy proxy;
    private boolean follow_redirects;
    private boolean allow_diffhostnames;
    private boolean allow_invalidcert;
    private boolean require_success;
    private KeyStore trust_store;
    private SSLSocketFactory socket_factory;
    private boolean ssl_initialized;
    private int response_code;
    private int content_length;
    private String response_message;
    private PasswordAuthentication password_authentication;
    private boolean interactive_mode;
    private boolean enable_revocation_test = false;
    private String url;
    private static Proxy default_proxy;
    private static KeyStore default_trust_store;
    private KeyStore key_store;
    private String keyAlias;
    private String key_store_password;
    private String request_method;

    private LinkedHashMap<String, Vector<String>> request_headers = new LinkedHashMap<String, Vector<String>>();

    private LinkedHashMap<String, Vector<String>> response_headers = new LinkedHashMap<String, Vector<String>>();

    private byte[] server_data;

    private X509Certificate[] server_certificates;

    /* Variables related to sending data to server. */
    private int timeout = 0;


    /**
     * Constructs an HTTPSWrapper object.
     */
    public HTTPSWrapper() {
    }


    /*
     * SSL initialization method.
     */
    private void initSSL() throws IOException {
        if (!ssl_initialized) {
            try {
                /////////////////////////////////////
                // Do we have a trust store?
                /////////////////////////////////////
                TrustManager[] trust_managers = null;
                if (allow_invalidcert) {
                    trust_managers = new TrustManager[]{new HttpsWrapperTrustManager()};
                    if (trust_store == null) {
                        trust_store = KeyStore.getInstance("JKS");
                    }
                } else if (trust_store != null) {
                    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
                    tmf.init(trust_store);
                    trust_managers = tmf.getTrustManagers();
                }

                /////////////////////////////////////
                // Do we have a key store?
                /////////////////////////////////////
                KeyManager[] key_managers = null;
                if (key_store != null) {
                    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
                    kmf.init(key_store, key_store_password.toCharArray());
                    key_managers = kmf.getKeyManagers();
                    if (keyAlias != null) {
                        final X509KeyManager orig_key_manager = (X509KeyManager) key_managers[0];
                        key_managers = new KeyManager[]{new X509KeyManager() {

                            @Override
                            public String chooseClientAlias(String[] key_type, Principal[] issuers, Socket socket) {
                                return keyAlias;
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
                SSLContext ctx = SSLContext.getInstance("TLS");
                ctx.init(key_managers, trust_managers, null);
                socket_factory = ctx.getSocketFactory();
            } catch (GeneralSecurityException gse) {
                throw new IOException(gse);
            }
            ssl_initialized = true;
        }
    }


    /**
     * Sets the Trust Store to use. The Trust Store is used to verify server
     * certificates in SSL negotiations.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Trust Store. <br><br>
     * <p>
     * To set your own Trust Store this method must be called before making
     * either a GET or POST request.
     *
     * @param store_name       Path to the Trust store file.
     * @param store_passphrase Passphrase to unlock Trust Store.
     * @throws IOException If something unexpected happens...
     */
    public void setTrustStore(String store_name, String store_passphrase) throws IOException {
        trust_store = KeyStoreReader.loadKeyStore(store_name, store_passphrase);
        ssl_initialized = false;
    }


    /**
     * Sets the default (app-wide) Trust Store to use. The Trust Store is used to verify server
     * certificates in SSL negotiations.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Trust Store. <br><br>
     *
     * @param store_name       Path to the Trust store file.
     * @param store_passphrase Passphrase to unlock Trust Store.
     * @throws IOException If something unexpected happens...
     */
    public static void setDefaultTrustStore(String store_name, String store_passphrase) throws IOException {
        default_trust_store = KeyStoreReader.loadKeyStore(store_name, store_passphrase);
    }


    /**
     * Sets the Trust Store to use. The Trust Store is used to verify server
     * certificates in SSL negotiations.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Trust Store. <br><br>
     * <p>
     * To set your own Trust Store this method must be called before making
     * either a GET or POST request.
     *
     * @param trust_store Initialized java KeyStore.
     */
    public void setTrustStore(KeyStore trust_store) {
        this.trust_store = trust_store;
        ssl_initialized = false;
    }


    /**
     * Sets the default (app-wide) Trust Store to use. The Trust Store is used to verify server
     * certificates in SSL negotiations.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Trust Store. <br><br>
     * <p>
     * To set your own Trust Store this method must be called before making
     * either a GET or POST request.
     *
     * @param trust_store Initialized java KeyStore.
     */
    public static void setDefaultTrustStore(KeyStore trust_store) {
        default_trust_store = trust_store;
    }


    /**
     * Sets the Key Store to use. The Key Store is used to authenticate
     * with using SSL.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Key Store (none). <br><br>
     * <p>
     * To set your own Key Store this method must be called before making
     * either a GET or POST request.
     *
     * @param key_store_password Password to private key
     * @param key_store          Initialized java KeyStore.
     */
    public void setKeyStore(KeyStore key_store, String key_store_password) {
        this.key_store = key_store;
        this.key_store_password = key_store_password;
        ssl_initialized = false;
    }


    /**
     * Sets the Key Store to use. The Key Store is used to authenticate
     * with using SSL.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will use the default
     * JDK Key Store (none). <br><br>
     * <p>
     * To set your own Key Store this method must be called before making
     * either a GET or POST request.
     *
     * @param key_store_file     PKCS #12 or Java Keystore file
     * @param key_store_password Password to private key
     * @throws IOException If something unexpected happens...
     */
    public void setKeyStore(String key_store_file, String key_store_password) throws IOException {
        setKeyStore(KeyStoreReader.loadKeyStore(key_store_file, key_store_password), key_store_password);
    }


    /**
     * Sets the Key Alias to use. The Key Alias is used to authenticate
     * with using SSL.<br><br>
     * <p>
     * If this method is not called the HTTPSWrapper will look for the
     * first suitable key. <br><br>
     * <p>
     * his method must be called before making either a GET or POST request.
     *
     * @param keyAlias name of selected key
     */
    public void setKeyAlias(String keyAlias) {
        this.keyAlias = keyAlias;
    }


    /**
     * Performs a POST request to the Web Server, posting data without any
     * interpretation of character encoding.
     *
     * @param url  Fully qualified URL to make connection to.
     * @param data Byte array to post to server.
     * @throws IOException If something unexpected happens...
     */
    public void makePostRequest(String url, byte[] data) throws IOException {
        /////////////////////////////
        // Prepare
        /////////////////////////////
        setupRequest(url, true);

        /////////////////////////////
        // Send POST data
        /////////////////////////////
        OutputStream post = conn.getOutputStream();
        post.write(data);
        post.flush();
        post.close();

        /////////////////////////////
        // Get response data
        /////////////////////////////
        getServerResponse();
    }


    /**
     * Performs a POST request to the Web Server, posting data with
     * UTF-8 character encoding.
     *
     * @param url  Fully qualified URL to make connection to.
     * @param data String to post to server.
     * @throws IOException If something unexpected happens...
     */
    public void makePostRequestUTF8(String url, String data) throws IOException {
        makePostRequest(url, data.getBytes("UTF-8"));
    }


    /* 
     * Sets up request. 
     */
    private void setupRequest(String url, boolean output) throws IOException {
        ///////////////////////////////////////////////
        // Clear the result
        ///////////////////////////////////////////////
        server_data = null;

        ///////////////////////////////////////////////
        // Clear the response header.
        ///////////////////////////////////////////////
        response_headers.clear();

        ///////////////////////////////////////////////
        // If HTTPS, setup the security pieces
        ///////////////////////////////////////////////
        this.url = url;
        boolean https_flag = false;
        if (url.startsWith("https:")) {
            if (trust_store == null && default_trust_store != null) {
                trust_store = default_trust_store;
                ssl_initialized = false;
            }
            // HTTPS connection.
            initSSL();
            https_flag = true;
        }

        ///////////////////////////////////////////////
        // Create the connection
        ///////////////////////////////////////////////
        conn = (proxy == null && default_proxy == null) ?
                (HttpURLConnection) new URL(url).openConnection()
                :
                (HttpURLConnection) new URL(url).openConnection(proxy == null ? default_proxy : proxy);
        conn.setAllowUserInteraction(false);

        ///////////////////////////////////////////////
        // HTTPS requires some extras
        ///////////////////////////////////////////////
        if (https_flag) {
            if (allow_diffhostnames) {
                ((HttpsURLConnection) conn).setHostnameVerifier(new HostnameVerifier() {
                    public boolean verify(String hostname, SSLSession session) {
                        return true;
                    }
                });
            }
            // ANDROID PATCH HERE

            if (socket_factory != null) {
                ((HttpsURLConnection) conn).setSSLSocketFactory(socket_factory);
            }
        }

        ///////////////////////////////////////////////
        // Set timeout if specified
        ///////////////////////////////////////////////
        if (timeout != 0) {
            conn.setReadTimeout(timeout);
        }

        ///////////////////////////////////////////////
        // Override GET or POST mode
        ///////////////////////////////////////////////
        if (request_method != null) {
            conn.setRequestMethod(request_method);
        }

        ///////////////////////////////////////////////
        // Set URI(GET) or Body(POST) mode
        ///////////////////////////////////////////////
        conn.setDoOutput(output);

        ///////////////////////////////////////////////
        // Set the redirect mode.  Note: false is default
        ///////////////////////////////////////////////
        conn.setInstanceFollowRedirects(follow_redirects);

        ///////////////////////////////////////////////
        // Output user-defined header data
        ///////////////////////////////////////////////
        for (String key : request_headers.keySet()) {
            for (String value : request_headers.get(key)) {
                conn.setRequestProperty(key, value);
            }
        }

        ///////////////////////////////////////////////
        // We are done with the request header
        ///////////////////////////////////////////////
        request_headers.clear();

        ///////////////////////////////////////////////
        // Calling you...
        ///////////////////////////////////////////////
        conn.setConnectTimeout(60000);
        conn.connect();

        if (https_flag) {
            server_certificates = (X509Certificate[]) (((HttpsURLConnection) conn).getServerCertificates());
        }
    }


    /**
     * Performs a GET request to the Web Server.
     *
     * @param url Fully qualified URL to make connection to.
     * @throws IOException If something unexpected happens...
     */
    public void makeGetRequest(String url) throws IOException {
        /////////////////////////////
        // Prepare
        /////////////////////////////
        setupRequest(url, false);

        /////////////////////////////
        // Get response data
        /////////////////////////////
        getServerResponse();
    }


    /*
     * Initializes connection to server and reads data from the server response. 
     * If data is not null, data is posted to server.
     */
    private void getServerResponse() throws IOException {
        ////////////////////////////////////////////
        // Read response data
        ////////////////////////////////////////////
        response_code = conn.getResponseCode();
        if (response_code == HttpURLConnection.HTTP_OK) {
            server_data = ArrayUtil.getByteArrayFromInputStream(conn.getInputStream());
        } else {
            InputStream is = conn.getErrorStream();
            if (is != null) {
                server_data = ArrayUtil.getByteArrayFromInputStream(conn.getErrorStream());
            }
        }

        ////////////////////////////////////////////
        // Read response header data
        ////////////////////////////////////////////
        Map<String, List<String>> headers = conn.getHeaderFields();
        for (String key : headers.keySet()) {
            if (key != null) // Protection against a bug in URLConnection
            {
                Vector<String> values = new Vector<String>();
                for (String value : headers.get(key)) {
                    values.add(value);
                }
                response_headers.put(key, values);
            }
        }
        content_length = conn.getContentLength();
        response_message = conn.getResponseMessage();

        ////////////////////////////////////////////
        // Close
        ////////////////////////////////////////////
        conn.disconnect();
        if (require_success && response_code != HttpURLConnection.HTTP_OK) {
            throw new IOException("Unexpected return code [" + response_code +
                    (response_message == null ? "" : " " + response_message) +
                    "] for url: " + url + (server_data == null ? "" : "\n" + getDataUTF8()));
        }
    }


    /**
     * Gets server response data as byte array.
     *
     * @return Byte array containing all received data as it was received from
     * the server, or null if no data was available.
     */
    public byte[] getData() {
        return server_data;
    }


    /**
     * Gets server response data as String in UTF-8 character encoding.
     *
     * @return String containing all received data in UTF-8 encoding,
     * or null if no data was available.
     * @throws IOException If something unexpected happens...
     */
    public String getDataUTF8() throws IOException {
        return (server_data == null) ? null : new String(server_data, "UTF-8");
    }


    /**
     * Override te default methods. <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param requestMethod method to use.
     */
    public void setRequestMethod(String requestMethod) {
        request_method = requestMethod;
    }


    /**
     * If true, responses other HTTP than 200 (OK) will throw an exception. <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param flag True to require success, else false.
     */
    public void setRequireSuccess(boolean flag) {
        require_success = flag;
    }


    /**
     * If true, client allows server certificates that are either
     * not valid yet or have expired. Default value is false.  <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param flag True to allow bad validity certificates, else false.
     */
    public void allowInvalidCert(boolean flag) {
        allow_invalidcert = flag;
    }


    /**
     * If true, client allows Common Name in server certificate
     * to differ from the server DNS name. Default value is false.<br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param flag True to allow different host names, else false.
     */
    public void allowDiffHostNames(boolean flag) {
        allow_diffhostnames = flag;
    }


    /**
     * If true, enable server certificate revocation checks. <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param flag The flag, Yeah
     */
    public void setServerCertificateRevocation(boolean flag) {
        enable_revocation_test = flag;
    }


    private static Proxy _setProxy(String host, int port) throws IOException {
        return host == null ? null : new Proxy(Proxy.Type.HTTP,
                new InetSocketAddress(InetAddress.getByName(host),
                        Integer.valueOf(port)));
    }


    /**
     * Sets up the proxy host and port to use. <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param host Host name or IP address of proxy. <tt>null</tt> removes any previous setting.
     * @param port Port number for proxy connection.
     * @throws IOException If something unexpected happens...
     */
    public void setProxy(String host, int port) throws IOException {
        proxy = _setProxy(host, port);
    }


    /**
     * Sets up the default (app-wide) proxy host and port to use. <br><br>
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param host Host name or IP address of proxy. <tt>null</tt> removes any previous setting.
     * @param port Port number for proxy connection.
     * @throws IOException If something unexpected happens...
     */
    public static void setDefaultProxy(String host, int port) throws IOException {
        default_proxy = _setProxy(host, port);
    }


    /**
     * Sets wheter or not the HTTPSWrapper should follow HTTP 3xx
     * redirects or not. Default is false.
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param flag Whether or not to follow redirects automatically.
     */
    public void setFollowRedirects(boolean flag) {
        follow_redirects = flag;
    }


    public void setInteractiveMode(boolean flag) {
        interactive_mode = flag;
    }


    /**
     * Sets the read timeout. Default is forever.
     * <p>
     * This method affects all proceeding requests. <br><br>
     *
     * @param timeout Timeout in milliseconds.
     */
    public void setTimeout(int timeout) {
        this.timeout = timeout;
        ;
    }


    /**
     * Sets an HTTP header value for a succeeding request. <br><br>
     *
     * @param name  Name of header to set.
     * @param value Value associated with the header.
     * @throws IOException If something unexpected happens...
     */
    public void setHeader(String name, String value) throws IOException {
        for (String key : request_headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                request_headers.get(key).add(value);
                return;
            }
        }
        Vector<String> v = new Vector<String>();
        v.add(value);
        request_headers.put(name, v);
    }


    /**
     * Returns the HTTP response code for the most recent request.
     *
     * @return The response code.
     */
    public int getResponseCode() {
        return response_code;
    }


    /**
     * Returns the HTTP response line for the most recent request.
     *
     * @return The response message.
     */
    public String getResponseMessage() {
        return response_message;
    }


    /**
     * Returns the value for the corresponding HTTP response header name.
     *
     * @param name Name to search for in HTTP header.
     * @return Value for the requested name, or null if not found.  If multiple
     * values exist, only the first found is returned.
     */
    public String getHeaderValue(String name) {
        for (String key : response_headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                return response_headers.get(key).elementAt(0);
            }
        }
        return null;
    }


    /**
     * Returns the values for the corresponding HTTP response header name.
     *
     * @param name Name to search for in HTTP header.
     * @return Values for the requested name, or null if not found.
     */
    public String[] getHeaderValues(String name) {
        for (String key : response_headers.keySet()) {
            if (key.equalsIgnoreCase(name)) {
                return response_headers.get(key).toArray(new String[0]);
            }
        }
        return null;
    }


    /**
     * Returns the response headers for this call.
     *
     * @return Structure containing all the headers and associated values for this call.
     */
    public LinkedHashMap<String, Vector<String>> getHeaders() {
        return response_headers;
    }


    /**
     * Gets content type of HTTP response.
     *
     * @return The full <code>Content-Type</code> of the HTTP response, or null if not available.
     */
    public String getRawContentType() {
        return getHeaderValue("Content-Type");
    }


    /**
     * Gets content type of HTTP response.
     *
     * @return The <code>Content-Type</code> minus any extra information of the HTTP response, or null if not available.
     */
    public String getContentType() {
        String ct = getRawContentType();
        if (ct == null) {
            return null;
        }
        int i = ct.indexOf(';');
        if (i > 0) {
            ct = ct.substring(0, i);
        }
        return ct.trim();
    }


    /**
     * Gets content encoding of HTTP response.
     *
     * @return The character encoding type of the HTTP response, or null if not available.
     */
    public String getCharacterEncoding() {
        String ct = getHeaderValue("Content-Type");
        int i = ct.indexOf("charset=");
        if (i > 0) {
            return ct.substring(i + 8).trim();
        }
        return null;
    }


    /**
     * Gets content length from HTTP response.
     *
     * @return The length of the HTTP response, or -1 if length is not
     * available.
     */
    public int getContentLength() {
        return content_length;
    }


    /**
     * Gets server certificates from HTTPS response.
     *
     * @return Server certificate path.
     */
    public X509Certificate[] getServerCertificates() {
        return server_certificates;
    }


    public void setUserIDPassword(String user_id, String password) {
        if (password_authentication == null) {
            Authenticator.setDefault(new Authenticator() {
                protected PasswordAuthentication getPasswordAuthentication() {
                    if (url != null && url.equals(getRequestingURL().toString())) {
                        if (interactive_mode) {
                            System.out.println("\nHTTP Authentication Request: " + url);
                        }
                        return password_authentication;
                    }
                    return null;
                }
            });
        }
        password_authentication = new PasswordAuthentication(user_id, password.toCharArray());
    }

    /*
     * TrustManager for the HTTPSWrapper. 
     * Makes it possible to configure the SSL Client behaviour
     * and to set the Trust Store to use.
     */
    private class HttpsWrapperTrustManager implements X509TrustManager {

        /*
         * Constructor
         */
        private HttpsWrapperTrustManager() throws IOException {
        }


        /*
         * Implements X509TrustManager.
         */
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        }


        /*
         * Handles server certificate validation. 
         * Flags for validity and certificate chain verification 
         * decides this functions behavior.
         *
         * Implements X509TrustManager.
         */
        public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            try {
                Set<TrustAnchor> trust = new HashSet<TrustAnchor>();
                // All CAs must in an *installed* CA path be valid as trust
                // anchors
                Enumeration<String> aliases = trust_store.aliases();
                while (aliases.hasMoreElements()) {
                    String alias = aliases.nextElement();
                    if (trust_store.isCertificateEntry(alias)) {
                        trust.add(new TrustAnchor((X509Certificate) trust_store.getCertificate(alias), null));
                    }
                }
                CertPathValidator cpv = CertPathValidator.getInstance("PKIX");
                PKIXParameters param = new PKIXParameters(trust);
                param.setDate(new Date());
                param.setRevocationEnabled(enable_revocation_test);
                List<X509Certificate> certchain = new ArrayList<X509Certificate>();
                for (X509Certificate cert : chain) {
                    if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
                        certchain.add(cert);
                    }
                }
                CertPath cp = CertificateFactory.getInstance("X.509").generateCertPath(certchain);
                cpv.validate(cp, param);
            } catch (GeneralSecurityException e) {
                if (!allow_invalidcert) {
                    throw new CertificateException(e);
                }
            }
        }


        /*
         * Implements X509TrustManager.
         */
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }

    }


    private static class CommandLine {

        Vector<CmdLineArgument> list = new Vector<CmdLineArgument>();

        int max_display;

        String helptext;

        HTTPSWrapper wrap = new HTTPSWrapper();

        private void bad(String what) {
            System.out.println("\n" + what);
            System.exit(3);
        }


        class CmdLineArgument {
            CmdLineArgumentGroup group;
            CmdLineArgumentGroup mutually_exclusive_group;
            String helptext;
            String command;
            String optargument;
            String defaultvalue;
            Vector<String> argvalue = new Vector<String>();
            CmdFrequency frequency;
            boolean found;

            CmdLineArgument(CmdLineArgumentGroup group,
                            String command,
                            String optargument,
                            String helptext,
                            CmdFrequency frequency,
                            String defaultvalue) {
                this.group = group;
                this.command = command;
                this.optargument = optargument;
                this.helptext = helptext;
                this.frequency = frequency;
                this.defaultvalue = defaultvalue;
                int i = command.length() + 1;
                if (optargument != null) {
                    i += optargument.length() + 3;
                }
                if (i > max_display) {
                    max_display = i;
                }
                for (CmdLineArgument c : list) {
                    if (c.command.equals(command)) {
                        System.out.println("\n****Duplicate command line init: " + command);
                        System.exit(3);
                    }
                }
                list.add(this);
            }

            int getInteger() throws IOException {
                return Integer.parseInt(getString());
            }

            String getString() throws IOException {
                if (argvalue.size() != 1) {
                    bad("Internal argument error for command: " + command);
                }
                return argvalue.elementAt(0).trim();
            }

        }

        enum CmdLineArgumentGroup {GENERAL,
                                   POST_OPERATION,
                                   GET_OPERATION,
                                   EE_ENTITY,
                                   CA_ENTITY}

        enum CmdFrequency {OPTIONAL,
                           SINGLE,
                           OPTIONAL_MULTIPLE,
                           MULTIPLE}

        CmdLineArgument create(CmdLineArgumentGroup group, String command, String optargument, String helptext, CmdFrequency frequency) {
            return new CmdLineArgument(group, command, optargument, helptext, frequency, null);
        }

        CmdLineArgument create(CmdLineArgumentGroup group, String command, String optargument, String helptext, String defaultvalue) {
            return new CmdLineArgument(group, command, optargument, helptext, CmdFrequency.OPTIONAL, defaultvalue);
        }


        void setMutuallyExclusive(CmdLineArgumentGroup group1, CmdLineArgumentGroup group2) {
            for (CmdLineArgument cla1 : list) {
                if (cla1.group == group1) {
                    for (CmdLineArgument cla2 : list) {
                        if (cla2.group == group2) {
                            cla1.mutually_exclusive_group = group2;
                            cla2.mutually_exclusive_group = group1;
                        }
                    }
                }
            }
        }

        void checkConsistency() throws IOException {
            for (CmdLineArgument cla1 : list) {
                if (cla1.found) {
                    // Now check for mutual exclusion....
                    for (CmdLineArgument cla2 : list) {
                        if (cla1.group == cla2.mutually_exclusive_group && cla2.found) {
                            bad("Command '-" + cla1.command + "' cannot be combined with '-" + cla2.command + "'");
                        }
                    }
                } else if (cla1.frequency == CmdFrequency.SINGLE || cla1.frequency == CmdFrequency.MULTIPLE) {
                    String other = "";
                    boolean bad = true;
                    for (CmdLineArgument cla2 : list) {
                        if (cla1.group == cla2.mutually_exclusive_group) {
                            if (cla2.found) {
                                bad = false;
                                break;
                            }
                            if (cla2.frequency == CmdFrequency.SINGLE || cla2.frequency == CmdFrequency.MULTIPLE) {
                                other = " or -" + cla2.command;
                                for (CmdLineArgument cla3 : list) {
                                    if (cla3.found && cla3.group == cla1.group) {
                                        other = "";
                                        break;
                                    }
                                }
                            }
                        }
                    }
                    if (bad) {
                        bad("Missing command: -" + cla1.command + other);
                    }
                } else if (cla1.frequency == CmdFrequency.OPTIONAL && cla1.defaultvalue != null) {
                    boolean do_it = true;
                    for (CmdLineArgument cla2 : list) {
                        if (cla1.group == cla2.mutually_exclusive_group) {
                            if (cla2.found) {
                                do_it = false;
                                break;
                            }
                        }
                    }
                    if (do_it) {
                        cla1.argvalue.add(cla1.defaultvalue);
                        cla1.found = true;
                    }
                }
            }
        }


        void printHelpLine() {
            if (helptext == null) return;
            int i = 0;
            for (int j = 0; j < helptext.length(); j++) {
                if (helptext.charAt(j) == ' ') {
                    if (j < 68 - max_display) {
                        i = j;
                    }
                }
            }
            if (i > 0 && helptext.length() >= 68 - max_display) {
                System.out.print(helptext.substring(0, i++));
                helptext = helptext.substring(i);
            } else {
                System.out.print(helptext);
                helptext = null;
            }
        }


        void show() {
            System.out.print("\nUsage: HTTPSWrapper options\n\n     OPTIONS\n\n");
            for (CmdLineArgument cla : list) {
                helptext = cla.helptext;
                if (cla.frequency == CmdFrequency.OPTIONAL || cla.frequency == CmdFrequency.OPTIONAL_MULTIPLE) {
                    helptext = "OPTIONAL.  " + helptext;
                    if (cla.frequency == CmdFrequency.OPTIONAL_MULTIPLE) {
                        helptext += ".  The command may be REPEATED";
                    }
                }
                System.out.print("       -" + cla.command);
                int i = cla.command.length() - 3;
                if (cla.optargument != null) {
                    i += cla.optargument.length() + 3;
                    System.out.print(" \"" + cla.optargument + "\"");
                }
                while (i++ < max_display) {
                    System.out.print(" ");
                }
                printHelpLine();
                System.out.println();
                if (cla.defaultvalue != null) {
                    System.out.print("           default: " + cla.defaultvalue);
                    i = cla.defaultvalue.length() + 9;
                    if (i < max_display) {
                        while (i++ < max_display) {
                            System.out.print(" ");
                        }
                        printHelpLine();
                    }
                    System.out.println();
                }
                while (helptext != null) {
                    i = -11;
                    while (i++ < max_display) {
                        System.out.print(" ");
                    }
                    printHelpLine();
                    System.out.println();
                }
                System.out.println();
            }
        }


        CmdLineArgument CMD_get_oper = create(CmdLineArgumentGroup.GET_OPERATION,
                "get", "URL",
                "Perform HTTP GET operation",
                CmdFrequency.SINGLE);

        CmdLineArgument CMD_post_oper = create(CmdLineArgumentGroup.POST_OPERATION,
                "post", "URL",
                "Perform HTTP POST operation",
                CmdFrequency.SINGLE);

        CmdLineArgument CMD_override_method = create(CmdLineArgumentGroup.GENERAL,
                "override", "method",
                "Override HTTP Method",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_data_file = create(CmdLineArgumentGroup.POST_OPERATION,
                "input", "file",
                "POSTed data file",
                CmdFrequency.SINGLE);

        CmdLineArgument CMD_mime_type = create(CmdLineArgumentGroup.POST_OPERATION,
                "type", "MIME-type",
                "MIME-type associated with POSTed data",
                "application/x-www-form-urlencoded");

        CmdLineArgument CMD_follow_redirs = create(CmdLineArgumentGroup.GENERAL,
                "redir", null,
                "Follow HTTP redirects (302)",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_dump_data = create(CmdLineArgumentGroup.GENERAL,
                "data", null,
                "Display data",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_dump_headers = create(CmdLineArgumentGroup.GENERAL,
                "headers", null,
                "Display headers",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_dump_certs = create(CmdLineArgumentGroup.GENERAL,
                "certificates", null,
                "Display TLS certificate path",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_user_id = create(CmdLineArgumentGroup.GENERAL,
                "user", "login-id",
                "HTTP Auth - User",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_password = create(CmdLineArgumentGroup.GENERAL,
                "pwd", "password",
                "HTTP Auth - Password",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_store_data = create(CmdLineArgumentGroup.GENERAL,
                "output", "file",
                "Write data to file",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_invalid_ok = create(CmdLineArgumentGroup.GENERAL,
                "accept/invalid", null,
                "Accept invalid server certificates",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_badnames_ok = create(CmdLineArgumentGroup.GENERAL,
                "accept/badname", null,
                "Accept non-matching host name(s) in certificates",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_require_ok = create(CmdLineArgumentGroup.GENERAL,
                "require/success", null,
                "Do not accept HTTP errors",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_timeout = create(CmdLineArgumentGroup.GENERAL,
                "timeout", "value",
                "Set timeout in milliseconds",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_setheader = create(CmdLineArgumentGroup.GENERAL,
                "setheader", "key:value",
                "Set HTTP header",
                CmdFrequency.OPTIONAL_MULTIPLE);

        CmdLineArgument CMD_truststore = create(CmdLineArgumentGroup.GENERAL,
                "truststore", "file",
                "Set external trust store",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_storepass = create(CmdLineArgumentGroup.GENERAL,
                "storepass", "password",
                "Set password of external trust store",
                "testing");

        CmdLineArgument CMD_keystore = create(CmdLineArgumentGroup.GENERAL,
                "keystore", "file",
                "Set external key store",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_p11lib = create(CmdLineArgumentGroup.GENERAL,
                "p11lib", "file",
                "Set PKCS11 library path.  If \"p11slot\" is not given the " +
                        "file is assumed to hold a PKCS11 configuration",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_p11slot = create(CmdLineArgumentGroup.GENERAL,
                "p11slot", "slot",
                "Set PKCS11 slot number.  If started with \"i\" slotListIndex is used",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_keypass = create(CmdLineArgumentGroup.GENERAL,
                "keypass", "password",
                "Set password of key",
                "testing");

        CmdLineArgument CMD_keyalias = create(CmdLineArgumentGroup.GENERAL,
                "keyalias", "alias",
                "Set alias of key",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_addprovider = create(CmdLineArgumentGroup.GENERAL,
                "provider", "class",
                "Add provider (also see \"provider-argument\")",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_provider_arg = create(CmdLineArgumentGroup.GENERAL,
                "provider-argument", "argument",
                "If \"provider\" needs an argument",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_proxyhost = create(CmdLineArgumentGroup.GENERAL,
                "proxyhost", "host-or-ip",
                "Set web proxy host",
                CmdFrequency.OPTIONAL);

        CmdLineArgument CMD_proxyport = create(CmdLineArgumentGroup.GENERAL,
                "proxyport", "port-number",
                "Set web proxy port number",
                CmdFrequency.OPTIONAL);


        CommandLine() {
            setMutuallyExclusive(CmdLineArgumentGroup.POST_OPERATION, CmdLineArgumentGroup.GET_OPERATION);
        }


        CmdLineArgument get(String argument) throws IOException {
            for (CmdLineArgument cla : list) {
                if (cla.command.equals(argument.substring(1))) {
                    if (cla.found && (cla.frequency == CmdFrequency.OPTIONAL || cla.frequency == CmdFrequency.SINGLE)) {
                        bad("Duplicate command: " + argument);
                    }
                    cla.found = true;
                    return cla;
                }
            }
            bad("No such command: " + argument);
            return null;  // For the parser only
        }


        void decodeCommandLine(String argv[]) throws IOException {
            if (argv.length == 0) {
                show();
                System.exit(3);
            }
            for (int i = 0; i < argv.length; i++) {
                String arg = argv[i];
                if (arg.indexOf('-') != 0) {
                    bad("Command '" + arg + "' MUST start with a '-'");
                }
                CmdLineArgument cla = get(arg);
                if (cla.optargument == null) continue;
                if (++i >= argv.length) {
                    bad("Missing argument for command: " + arg);
                }
                String opt = argv[i];
                if (opt.indexOf('-') == 0) {
                    bad("Argument to command '" + arg + "' MUST NOT start with a '-'");
                }
                cla.argvalue.add(opt);
            }
            checkConsistency();
        }


        void initiateProviderKeyStore(Provider provider) throws Exception {
            String prov = null;
            for (Provider.Service ps : provider.getServices()) {
                if (ps.getType().equals("KeyStore")) {
                    prov = ps.getAlgorithm();
                }
            }
            Security.addProvider(provider);
            KeyStore ks = KeyStore.getInstance(prov, provider);
            ks.load(CMD_keystore.found ? new FileInputStream(CMD_keystore.getString()) : null,
                    CMD_keypass.found ? CMD_keypass.getString().toCharArray() : null);
            wrap.setKeyStore(ks, CMD_keypass.getString());
            CMD_keystore.found = false;
        }


        void execute(String argv[]) throws Exception {
            decodeCommandLine(argv);

            if (CMD_proxyhost.found != CMD_proxyport.found) {
                bad("Missing command: -" + (CMD_proxyhost.found ?
                        CMD_proxyport.command : CMD_proxyhost.command));
            }

            wrap.setInteractiveMode(true);

            if (CMD_user_id.found || CMD_password.found) {
                if (CMD_user_id.found != CMD_password.found) {
                    bad("Missing command: -" + (CMD_user_id.found ?
                            CMD_password.command : CMD_user_id.command));
                }
                wrap.setUserIDPassword(CMD_user_id.getString(), CMD_password.getString());
            }

            if (CMD_proxyhost.found) {
                wrap.setProxy(CMD_proxyhost.getString(), CMD_proxyport.getInteger());
            }

            if (CMD_override_method.found) {
                wrap.setRequestMethod(CMD_override_method.getString());
            }

            if (CMD_timeout.found) {
                wrap.setTimeout(CMD_timeout.getInteger());
            }

            if (CMD_follow_redirs.found) {
                wrap.setFollowRedirects(true);
            }

            if (CMD_badnames_ok.found) {
                wrap.allowDiffHostNames(true);
            }

            if (CMD_require_ok.found) {
                wrap.setRequireSuccess(true);
            }

            if (CMD_invalid_ok.found) {
                wrap.allowInvalidCert(true);
            }

            if (CMD_setheader.found) {
                for (String value : CMD_setheader.argvalue) {
                    value = value.trim();
                    int i = value.indexOf(':');
                    if (i <= 0 || i == value.length() - 1) {
                        bad("Misformed header argument: " + value);
                    }
                    wrap.setHeader(value.substring(0, i), value.substring(i + 1));
                }
            }

            if (CMD_mime_type.found) {
                wrap.setHeader("Content-Type", CMD_mime_type.getString());
            }

            if (CMD_p11lib.found) {
                String p11wrapper = "sun.security.pkcs11.SunPKCS11";
                if (CMD_addprovider.found) {
                    p11wrapper = CMD_addprovider.getString();
                    CMD_addprovider.found = false;
                }
                if (CMD_p11slot.found) {
                    String slot = CMD_p11slot.getString();
                    String slot_label = "slot";
                    if (slot.charAt(0) == 'i') {
                        slot_label = "slotListIndex";
                        slot = slot.substring(1);
                    }
                    ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    PrintWriter pw = new PrintWriter(baos);
                    pw.println("name = " + new File(CMD_p11lib.getString()).getName() + "-" + slot_label + slot);
                    pw.println("library = " + CMD_p11lib.getString());
                    pw.println(slot_label + " = " + slot);
                    pw.flush();
                    pw.close();
                    initiateProviderKeyStore((Provider) Class.forName(p11wrapper).
                            getConstructor(InputStream.class).newInstance(new ByteArrayInputStream(baos.toByteArray())));
                } else {
                    initiateProviderKeyStore((Provider) Class.forName(p11wrapper).
                            getConstructor(String.class).newInstance(CMD_p11lib.getString()));
                }
            }

            if (CMD_addprovider.found) {
                initiateProviderKeyStore(CMD_provider_arg.found ?
                        (Provider) Class.forName(CMD_addprovider.getString()).getConstructor(String.class).newInstance(CMD_provider_arg.getString())
                        :
                        (Provider) Class.forName(CMD_addprovider.getString()).newInstance());
            }

            if (CMD_truststore.found) {
                wrap.setTrustStore(CMD_truststore.getString(),
                        CMD_storepass.getString());
            }

            if (CMD_keystore.found) {
                wrap.setKeyStore(CMD_keystore.getString(),
                        CMD_keypass.getString());
            }

            if (CMD_keyalias.found) {
                wrap.setKeyAlias(CMD_keyalias.getString());
            }

            if (CMD_get_oper.found) {
                wrap.makeGetRequest(CMD_get_oper.getString());
            } else {
                wrap.makePostRequest(CMD_post_oper.getString(), ArrayUtil.readFile(CMD_data_file.getString()));
            }

            if (CMD_dump_certs.found) {
                for (X509Certificate certificate : wrap.server_certificates) {
                    System.out.println("\nCertificate:\n" + new CertificateInfo(certificate).toString());
                }
            }

            if (CMD_dump_headers.found) {
                System.out.println("\nHeaders:\n" + wrap.getResponseCode() + " " + wrap.getResponseMessage());
                LinkedHashMap<String, Vector<String>> headers = wrap.getHeaders();
                for (String key : headers.keySet()) {
                    for (String value : headers.get(key)) {
                        System.out.println(key + ": " + value);
                    }
                }
            }

            if (CMD_dump_data.found) {
                System.out.println("\nData:\n" + wrap.getDataUTF8());
            }

            if (CMD_store_data.found) {
                ArrayUtil.writeFile(CMD_store_data.getString(), wrap.getData());
            }

        }
    }

    /**
     * Command-line interface to the HTTPSWrapper.
     *
     * @param argv Command line parameters
     * @throws Exception If something unexpected happens...
     */
    static public void main(String[] argv) throws Exception {
        new CommandLine().execute(argv);
    }

}

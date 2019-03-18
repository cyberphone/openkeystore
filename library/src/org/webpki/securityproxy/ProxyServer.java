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
import java.io.ByteArrayOutputStream;

import java.util.Date;
import java.util.HashMap;
import java.util.Vector;

import java.util.logging.Logger;

import javax.servlet.ServletException;
import javax.servlet.ServletInputStream;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletRequest;

/**
 * Security proxy server core logic.
 * Called by a proxy servlet application.
 *
 * @see ProxyChannelServlet
 */
public class ProxyServer {
    /**
     * web.xml servlet init parameter.
     * Mandatory name of proxy service.
     * An "Outer Service" must refer to the same name in {@link #getInstance(String)}.
     *
     * @see ProxyChannelServlet
     */
    public static final String PROXY_SERVICE_PROPERTY = "proxy-service-name";

    /**
     * web.xml servlet init parameter.
     * Optional remote IP address check for systems using shared ports.
     *
     * @see ProxyChannelServlet
     */
    public static final String PROXY_REMOTE_ADDRESS_PROPERTY = "proxy-remote-address";

    /**
     * web.xml servlet init parameter.
     * Optional server port check for systems using shared ports.
     *
     * @see ProxyChannelServlet
     */
    public static final String PROXY_SERVER_PORT_PROPERTY = "proxy-server-port";

    private static final long TIME_MARGIN = 600000;  // 10 minutes is a pretty good margin..,

    private static Logger logger = Logger.getLogger(ProxyServer.class.getName());

    private static HashMap<String, ProxyServer> services = new HashMap<String, ProxyServer>();

    private Vector<RequestDescriptor> response_queue = new Vector<RequestDescriptor>();

    private Vector<RequestDescriptor> waiting_callers = new Vector<RequestDescriptor>();

    private Vector<ServerUploadHandler> upload_event_subscribers = new Vector<ServerUploadHandler>();

    private Vector<ProxyRequest> proxies = new Vector<ProxyRequest>();

    private long next_caller_id;

    private long next_proxy_id;

    private String service_name;  // Optional

    private InternalServerConfiguration server_configuration;

    private JavaRequestInterface last_request;

    private int response_timeout_errors;

    private int request_timeout_errors;

    private Class<? extends ProxyServerErrorFactory> error_container;

    private ProxyServer() {
    }

    /**
     * Create proxy service instance.
     * Note that there can only be one instance of a specific named service running in a single JVM.
     *
     * @param name_of_service Unique name
     * @return ProxyServer
     */
    public static ProxyServer getInstance(String name_of_service) {
        if (name_of_service == null || name_of_service.length() == 0) {
            throw new RuntimeException("Proxy instance name is missing or null");
        }
        synchronized (services) {
            ProxyServer service = services.get(name_of_service);
            if (service == null) {
                services.put(name_of_service, service = new ProxyServer());
                service.service_name = name_of_service;
                logger.info("Service=" + name_of_service + " created");
            }
            return service;
        }
    }

    public static void outputHTTPResponse(HttpServletResponse response, HTTPResponseWrapper http_data) throws IOException {
        if (http_data.error_status == 0) {
            //////////////////////////////////////////////////
            // Normal HTTP response, output headers as well 
            //////////////////////////////////////////////////
            response.setContentLength(http_data.data.length);
            response.setContentType(http_data.mimeType);
            for (String name : http_data.headers.keySet()) {
                response.setHeader(name, http_data.headers.get(name));
            }
            response.getOutputStream().write(http_data.data);
        } else if (http_data.error_status == HttpServletResponse.SC_MOVED_TEMPORARILY) {
            response.sendRedirect(http_data.string_data);
        } else {
            //////////////////////////////////////////
            // HTTP error response
            //////////////////////////////////////////
            response.sendError(http_data.error_status, http_data.string_data);
        }
    }

    public void setProxyServerErrorFactory(Class<? extends ProxyServerErrorFactory> error_container) {
        this.error_container = error_container;
    }

    public synchronized void addUploadEventHandler(ServerUploadHandler handler) {
        upload_event_subscribers.add(handler);
    }

    public synchronized void deleteUploadEventHandler(ServerUploadHandler handler) {
        upload_event_subscribers.remove(handler);
    }

    public synchronized boolean isReady() {
        return server_configuration != null;
    }

    private class Synchronizer {

        boolean touched;
        boolean timeout_flag;

        synchronized boolean perform(int timeout) {
            while (!touched && !timeout_flag) {
                try {
                    wait(timeout);
                } catch (InterruptedException e) {
                    return false;
                }
                timeout_flag = true;
            }
            return touched;
        }

        synchronized void haveData4You() {
            touched = true;
            notify();
        }
    }

    private abstract class Caller {
        abstract boolean transactRequest() throws IOException, ServletException;

        abstract void transactResponse() throws IOException, ServletException;

        abstract void transactProxy() throws IOException, ServletException;
    }

    private class RequestDescriptor extends Caller {
        HttpServletResponse response;
        JavaResponseInterface java_response;  // If response == null java_response must be defined...
        InternalRequestObject request_object;
        InternalResponseObject response_object;
        ProxyRequest proxy;
        Synchronizer request_waiter = new Synchronizer();
        Synchronizer response_waiter = new Synchronizer();

        void setProxyWorker(ProxyRequest proxy) {
            this.proxy = proxy;
            this.proxy.request_descriptor = this;
        }

        boolean transactRequest() throws IOException, ServletException {
            //////////////////////////////////////////////////
            // No proxy available, wait for one (or die)...
            //////////////////////////////////////////////////
            if (request_waiter.perform(server_configuration.request_timeout)) {
                return true;
            } else {
                request_timeout_errors++;
                cleanUpAfterFailedCall(this, "Call request timeout");
                return false;
            }
        }

        void transactProxy() throws IOException, ServletException {
            ////////////////////////////////////////////////////////////////
            // We have a request and a now freed proxy.
            ////////////////////////////////////////////////////////////////
            request_waiter.haveData4You(); // Get out of the hanging
            proxy.proxy_worker.haveData4You(); // Proxy: just do it!
            proxy.transactProxy();
        }

        void transactResponse() throws IOException, ServletException {
            if (response_waiter.perform(server_configuration.request_timeout)) {
                if (response_object == null) {
                    return;  // Special case: Restart
                }
                if (response == null) {
                    try {
                        java_response = (JavaResponseInterface) InternalObjectStream.readObject(response_object.response_data.data, request_object.proxy_request);
                    } catch (ClassNotFoundException e) {
                        throw new IOException(e);
                    }
                } else {
                    outputHTTPResponse(response, response_object.response_data);
                }
            } else {
                response_timeout_errors++;
                cleanUpAfterFailedCall(this, "Call response timeout");
            }
        }
    }

    private class ProxyRequest extends Caller {
        HttpServletResponse proxy_response;
        long proxy_id;
        Synchronizer proxy_worker = new Synchronizer();
        RequestDescriptor request_descriptor;

        void setCaller(RequestDescriptor request_descriptor) {
            this.request_descriptor = request_descriptor;
        }

        boolean transactRequest() throws IOException, ServletException {
            //////////////////////////////////////////////////////////
            // We had a free proxy to serve the request in question!
            //////////////////////////////////////////////////////////
            proxy_worker.haveData4You(); // Proxy: just do it!
            return true;
        }

        void transactProxy() throws IOException, ServletException {
            //////////////////////////////////////////////////////////
            // We have a proxy but no one is currently requesting it.
            // We simply have to wait for a timeout or a real task.
            //////////////////////////////////////////////////////////
            synchronized (proxy_worker) {
                if (proxy_worker.perform(server_configuration.proxy_timeout)) {
                    // We got some real data!
                    // However, we may also just be restarting...
                    if (request_descriptor == null) {
                        proxy_response.setStatus(HttpServletResponse.SC_OK);
                    } else {
                        proxy_response.getOutputStream().write(InternalObjectStream.writeObject(request_descriptor.request_object));
                    }
                } else {
                    // We never got a hit and have to remove this proxy from the list...
                    proxy_response.setStatus(HttpServletResponse.SC_OK);
                    for (ProxyRequest proxy : proxies.toArray(new ProxyRequest[0])) {
                        if (proxy.proxy_id == proxy_id) {
                            proxies.remove(proxy);
                            break;
                        }
                    }
                }
            }
        }

        void transactResponse() throws IOException, ServletException {
            request_descriptor.transactResponse();
        }
    }

    private void returnInternalFailure(HttpServletResponse response, String message) throws IOException {
        logger.severe(message);
        if (response == null) {
            throw new IOException(message);
        }
        if (error_container == null) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
        } else {
            try {
                ProxyServerErrorFactory server_error = error_container.newInstance();
                server_error.setMessage(message);
                response.setContentType(server_error.getMimeType());
                response.getOutputStream().write(server_error.getContent());
            } catch (InstantiationException e) {
                throw new IOException(e);
            } catch (IllegalAccessException e) {
                throw new IOException(e);
            }
        }
    }

    private void returnProxyFailure(HttpServletResponse response, String message) throws IOException {
        logger.severe(message);
        if (response == null) {
            throw new IOException(message);
        }
        response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, message);
    }

    /**
     * Proxy server status method.
     * <p>
     *
     * @return The number of proxy channels that are in a waiting state.
     */
    public synchronized int getProxyQueueLength() {
        return proxies.size();
    }

    /**
     * Proxy server status method.
     * <p>
     *
     * @return The number of request timeout errors occurred so far.
     */
    public int getRequestTimeouts() {
        return request_timeout_errors;
    }

    /**
     * Proxy server status method.
     * <p>
     *
     * @return The number of response timeout errors occurred so far.
     */
    public int getResponseTimeouts() {
        return response_timeout_errors;
    }

    /**
     * Proxy server status method.
     * <p>
     *
     * @return The last (if any) request object. Will be <b>null</b> if
     * there has been no external access yet.
     */
    public synchronized JavaRequestInterface getLastRequestObject() {
        return last_request;
    }

    /**
     * Proxy server status method.
     * <p>
     *
     * @return The instance ID of the proxy client. Will be <b>null</b> if
     * the proxy client has not yet called the proxy server.
     */
    public synchronized String getProxyClientID() {
        return server_configuration == null ? null : server_configuration.client_id;
    }

    private synchronized void cleanUpAfterFailedCall(RequestDescriptor request_descriptor, String err) throws IOException {
        long caller_id = request_descriptor.request_object.caller_id;
        for (RequestDescriptor rd : waiting_callers.toArray(new RequestDescriptor[0])) {
            if (rd.request_object.caller_id == caller_id) {
                waiting_callers.remove(rd);
                logger.info("Request queue object removed after fail");
                break;
            }
        }
        for (RequestDescriptor rd : response_queue.toArray(new RequestDescriptor[0])) {
            if (rd.request_object.caller_id == caller_id) {
                response_queue.remove(rd);
                logger.info("Response queue object removed after fail");
                break;
            }
        }
        returnInternalFailure(request_descriptor.response, "Internal server error: " + err);
    }

    private synchronized Caller processRequest(HttpServletResponse response, JavaRequestInterface request_object) throws IOException, ServletException {
        // Create a descriptor
        RequestDescriptor rd = new RequestDescriptor();
        rd.response = response;
        rd.request_object = new InternalRequestObject(last_request = request_object, next_caller_id++, response == null);
        response_queue.add(rd);

        // Now check if there is a proxy that can take this request
        if (proxies.isEmpty()) {
            // No - put in waiting list
            waiting_callers.add(rd);
            return rd;
        }
        // Yes - take it!
        ProxyRequest preq = proxies.remove(0);
        preq.setCaller(rd);
        return preq;
    }

    private JavaResponseInterface internalProcessCall(JavaRequestInterface proxy_request_object, HttpServletResponse response) throws IOException {
        try {
            ////////////////////////////////////////////////////////////////////////////////
            // Perform as much as possible of the "heavy" stuff outside of synchronization
            ////////////////////////////////////////////////////////////////////////////////

            if (server_configuration == null) {
                returnInternalFailure(response, "Service " + service_name + " not started yet!");
                return null;
            }

            ////////////////////////////////////////////////////////////////////
            // Insert request into queues etc.
            ////////////////////////////////////////////////////////////////////
            Caller ci = processRequest(response, proxy_request_object);

            ///////////////////////////////////////////////////
            // Now process the action of the request part
            ///////////////////////////////////////////////////
            if (ci.transactRequest()) {

                ////////////////////////////////////////////////////////
                // Success! Now process the action of the response part
                ////////////////////////////////////////////////////////
                ci.transactResponse();
            }
            return ci instanceof ProxyRequest ? ((ProxyRequest) ci).request_descriptor.java_response : ((RequestDescriptor) ci).java_response;
        } catch (ServletException e) {
            throw new IOException(e);
        }
    }

    /**
     * Proxy external call handler.
     * <p>
     * This method forwards an external call through the proxy tunnel, as well
     * as returning the associated response data.
     *
     * @param proxy_request_object The request data object.
     * @param response             The response object of the external call Servlet.
     * @throws IOException If something unexpected happens...
     */

    public void processCall(JavaRequestInterface proxy_request_object, HttpServletResponse response) throws IOException {
        internalProcessCall(proxy_request_object, response);
    }

    /**
     * Proxy external call handler.
     * <p>
     * This method forwards an external call through the proxy tunnel, as well
     * as returning the associated response data.
     *
     * @param proxy_request_object The request data object.
     * @return A Java object
     * @throws IOException If something unexpected happens...
     */
    public JavaResponseInterface processCall(JavaRequestInterface proxy_request_object) throws IOException {
        return internalProcessCall(proxy_request_object, null);
    }

    private synchronized RequestDescriptor findProxyRequest(long caller_id) {
        for (RequestDescriptor rd : response_queue.toArray(new RequestDescriptor[0])) {
            if (rd.request_object.caller_id == caller_id) {
                response_queue.remove(rd);
                return rd;
            }
        }
        return null;
    }

    private synchronized Caller addProxyWorker(HttpServletResponse response) throws IOException, ServletException {
        // Create a descriptor
        ProxyRequest preq = new ProxyRequest();
        preq.proxy_response = response;
        preq.proxy_id = next_proxy_id++;

        // Now check if there is a caller in need for some help
        if (waiting_callers.isEmpty()) {
            // No - just go and wait
            proxies.add(preq);
            return preq;
        }
        // Yes - take it!
        RequestDescriptor pd = waiting_callers.remove(0);
        pd.setProxyWorker(preq);
        return pd;
    }

    private synchronized void resetProxy(InternalServerConfiguration server_conf) {
        next_caller_id = 0;
        next_proxy_id = 0;
        response_timeout_errors = 0;
        request_timeout_errors = 0;
        last_request = null;

        ////////////////////////////////////////////////////////////////////////////////
        // Remove any active queues and locks
        ////////////////////////////////////////////////////////////////////////////////
        synchronized (proxies) {
            while (!proxies.isEmpty()) {
                proxies.remove(0).proxy_worker.haveData4You();
            }
        }
        resetRequest(response_queue);
        resetRequest(waiting_callers);

        ////////////////////////////////////////////////////////////////////////////////
        // Set the new configuration
        ////////////////////////////////////////////////////////////////////////////////
        server_configuration = server_conf;
        logger.info((server_conf == null ? "Resetting" : "Starting") + " Service=" + service_name + (server_conf == null ? "" : " ID=" + server_conf.client_id));
    }

    private void resetRequest(Vector<RequestDescriptor> request) {
        synchronized (request) {
            while (!request.isEmpty()) {
                RequestDescriptor rd = request.remove(0);
                rd.response_waiter.haveData4You();
                rd.request_waiter.haveData4You();
            }
        }
    }

    /**
     * Proxy server reset. Clears all internal variables and states. Typically
     * called by context destruction/reload in Servlets.
     */
    public void resetProxy() {
        resetProxy(null);
    }

    private boolean wrongClientID(InternalClientObject client_object, HttpServletResponse response) throws IOException {
        if (server_configuration == null) {
            returnProxyFailure(response, "Proxy server not ready");
            return true;
        }
        if (server_configuration.client_id.equals(client_object.client_id)) {
            return false;
        }
        returnProxyFailure(response, "Proxy client ID error " + server_configuration.client_id + " versus " + client_object.client_id);
        return true;
    }

    /**
     * Proxy client call handler.
     * <p>
     * This method processes a call from the proxy client.
     *
     * @param request  The request object of the proxy server Servlet.
     * @param response The response object of the proxy server Servlet.
     * @throws IOException      If something unexpected happens...
     * @throws ServletException If something unexpected happens...
     */
    void processProxyCall(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        ////////////////////////////////////////////////////////////////////////////////
        // Perform as much as possible of the "heavy" stuff outside of synchronization
        ////////////////////////////////////////////////////////////////////////////////
        ServletInputStream is = request.getInputStream();
        byte[] buf = new byte[4096];
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        int n;
        while ((n = is.read(buf)) != -1) {
            baos.write(buf, 0, n);
        }
        byte[] data = baos.toByteArray();

        /////////////////////////////////////////////////
        // Ready to process an authenticated call
        /////////////////////////////////////////////////
        try {
            InternalClientObject client_object = (InternalClientObject) InternalObjectStream.readObject(data, this);
            long serverTime = new Date().getTime();
            if (client_object.time_stamp > serverTime + TIME_MARGIN ||
                    client_object.time_stamp < serverTime - TIME_MARGIN) {
                returnProxyFailure(response, "Proxy client/server time diff >" + TIME_MARGIN + " milliseconds");
                return;
            }
            if (client_object instanceof InternalServerConfiguration) {

                ////////////////////////////////////////////////
                // First call. Reset all, get configuration
                ////////////////////////////////////////////////
                resetProxy((InternalServerConfiguration) client_object);
                response.setStatus(HttpServletResponse.SC_OK);
                return;
            } else if (client_object instanceof InternalResponseObject) {
                ////////////////////////////////////////////////
                // Data to process!
                ////////////////////////////////////////////////
                InternalResponseObject ro = (InternalResponseObject) client_object;
                if (wrongClientID(ro, response)) {
                    return;
                }
                RequestDescriptor rd = findProxyRequest(ro.caller_id);
                if (rd == null) {
                    logger.severe("Missing caller: " + ro.caller_id);
                } else {
                    rd.response_object = ro;
                    rd.response_waiter.haveData4You();
                }
                if (ro.return_immediately) {
                    response.setStatus(HttpServletResponse.SC_OK);
                    return;
                }
            } else if (client_object instanceof InternalUploadObject) {
                ////////////////////////////////////////////////
                // Must be an "Upload" client_object
                ////////////////////////////////////////////////
                InternalUploadObject upload = (InternalUploadObject) client_object;
                if (wrongClientID(upload, response)) {
                    return;
                }
                if (upload_event_subscribers.isEmpty()) {
                    returnProxyFailure(response, "No upload handler, " + service_name + " service not ready?");
                    return;
                }
                for (ServerUploadHandler handler : upload_event_subscribers) {
                    handler.handleUploadedData(upload.getPayload(handler));
                }
            } else {
                ////////////////////////////////////////////////
                // Must be an "Idle" client_object
                ////////////////////////////////////////////////
                InternalIdleObject idle = (InternalIdleObject) client_object;
                if (wrongClientID(idle, response)) {
                    return;
                }
            }
        } catch (ClassNotFoundException e) {
            logger.severe(e.getMessage());
            returnProxyFailure(response, "Unrecognized object (check versions)");
            return;
        }
        Caller ci = addProxyWorker(response);
        ci.transactProxy();
    }
}

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

import java.net.InetAddress;
import java.net.UnknownHostException;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletConfig;
import javax.servlet.ServletException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServlet;


/**
 * Proxy channel servlet.
 * <p>
 * This is the actual proxy channel servlet that forwards "Outer Service" proxy requests
 * into the {@link ProxyServer} instance.   It is configured by an external "web.xml" file.
 * <pre style="margin-left:20pt">&lt;?xml version="1.0" encoding="UTF-8"?&gt;

 &lt;web-app version="2.5"
 xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
 xmlns="http://java.sun.com/xml/ns/javaee"
 xmlns:web="http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"
 xsi:schemaLocation="http://java.sun.com/xml/ns/javaee http://java.sun.com/xml/ns/javaee/web-app_2_5.xsd"&gt;

 &lt;display-name&gt;Sample Proxy Channel&lt;/display-name&gt;

 &lt;servlet&gt;
 &lt;servlet-name&gt;ProxyChannelServlet&lt;/servlet-name&gt;
 &lt;servlet-class&gt;org.webpki.securityproxy.ProxyChannelServlet&lt;/servlet-class&gt;
 &lt;init-param&gt;
 &lt;description&gt;Mandatory unique proxy service name&lt;/description&gt;
 &lt;param-name&gt;proxy-service-name&lt;/param-name&gt;
 &lt;param-value&gt;Proxy.Demo&lt;/param-value&gt;
 &lt;/init-param&gt;
 &lt;!-- If you use a firewall, the following should not be necessary --&gt;
 &lt;!--
 &lt;init-param&gt;
 &lt;description&gt;Optional proxy remote address check.
 You may use an IP address or a resolvable DNS name.&lt;/description&gt;
 &lt;param-name&gt;proxy-remote-address&lt;/param-name&gt;
 &lt;param-value&gt;192.168.0.204&lt;/param-value&gt;
 &lt;/init-param&gt;
 --&gt;
 &lt;!-- If you use a firewall, the following should not be necessary --&gt;
 &lt;!--
 &lt;init-param&gt;
 &lt;description&gt;Optional proxy port check&lt;/description&gt;
 &lt;param-name&gt;proxy-server-port&lt;/param-name&gt;
 &lt;param-value&gt;9090&lt;/param-value&gt;
 &lt;/init-param&gt;
 --&gt;
 &lt;/servlet&gt;

 &lt;servlet-mapping&gt;
 &lt;servlet-name&gt;ProxyChannelServlet&lt;/servlet-name&gt;
 &lt;url-pattern&gt;/proxychannel&lt;/url-pattern&gt;
 &lt;/servlet-mapping&gt;

 &lt;/web-app&gt;

</pre>
 * Note that the servlet URI may be adapted to match the rest of the "Outer Service".
 */
public class ProxyChannelServlet extends HttpServlet {
    private static final long serialVersionUID = 1L;

    private static Logger logger = Logger.getLogger(ProxyChannelServlet.class.getCanonicalName());

    private String name_of_service;

    private String remote_address;

    private Integer server_port;

    private ProxyServer proxy_server;

    private String getHostBinding() {
        return (remote_address == null ? "*" : remote_address) +
                ":" +
                (server_port == null ? "*" : server_port.toString());
    }

    @Override
    public void init(ServletConfig config) throws ServletException {
        super.init(config);
        remote_address = config.getInitParameter(ProxyServer.PROXY_REMOTE_ADDRESS_PROPERTY);
        if (remote_address != null && remote_address.matches(".*[a-z,A-Z,_,\\-].*")) {
            try {
                remote_address = InetAddress.getByName(remote_address).getHostAddress();
            } catch (UnknownHostException e) {
                logger.severe("Host '" + remote_address + "' not resolvable");
                remote_address = "N/A";
            }
        }
        String port = config.getInitParameter(ProxyServer.PROXY_SERVER_PORT_PROPERTY);
        if (port != null) {
            server_port = new Integer(port);
        }
        name_of_service = config.getInitParameter(ProxyServer.PROXY_SERVICE_PROPERTY);
        if (name_of_service == null) {
            throw new ServletException("Servlet property '" + ProxyServer.PROXY_SERVICE_PROPERTY + "' is undefined!");
        }
        logger.info("Host binding for " + name_of_service + "=" + getHostBinding());
        proxy_server = ProxyServer.getInstance(name_of_service);
    }

    @Override
    public void doPost(HttpServletRequest request, HttpServletResponse response) throws IOException, ServletException {
        if ((remote_address != null && !remote_address.equals(request.getRemoteAddr())) ||
                (server_port != null && server_port != request.getServerPort())) {
            logger.log(Level.WARNING, "Illegal access to " + name_of_service + " from: " +
                    request.getRemoteAddr() + ":" + request.getServerPort() +
                    " expected: " + getHostBinding());
            response.setStatus(HttpServletResponse.SC_FORBIDDEN);
        } else {
            proxy_server.processProxyCall(request, response);
        }
    }
}

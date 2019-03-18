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
import java.util.Enumeration;
import java.util.Properties;
import java.util.Vector;

import javax.servlet.ServletContextEvent;

public class InitPropertyReader {

    Properties properties;

    public void initProperties(ServletContextEvent event) {
        properties = new Properties();
        @SuppressWarnings("unchecked")
        Enumeration<String> keys = event.getServletContext().getInitParameterNames();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            properties.put(key, event.getServletContext().getInitParameter(key));
        }
    }

    private String getPropertyStringUnconditional(String name) throws IOException {
        String value = properties.getProperty(name);
        if (value == null) {
            throw new IOException("Property: " + name + " missing");
        }
        return value;
    }

    public String getPropertyStringConditional(String name) throws IOException {
        return hasProperty(name) ? getPropertyString(name) : null;
    }

    public String getPropertyString(String name) throws IOException {
        return getPropertyStringUnconditional(name);
    }

    public String[] getPropertyStringList(String name) throws IOException {
        String res = getPropertyString(name);
        Vector<String> list = new Vector<String>();
        boolean keepon = true;
        while (keepon) {
            String element;
            int i = res.indexOf(',');
            if (i < 0) {
                element = res;
                keepon = false;
            } else {
                element = res.substring(0, i);
                res = res.substring(i + 1);
            }
            element = element.trim();
            if (element.length() == 0)
                throw new IOException("List '" + name + "' has syntax problems");
            list.add(element);
        }
        if (list.isEmpty()) throw new IOException("List '" + name + "' is empty");
        return list.toArray(new String[0]);
    }

    public int getPropertyInt(String name) throws IOException {
        return Integer.parseInt(getPropertyStringUnconditional(name));
    }

    public boolean getPropertyBoolean(String name) throws IOException {
        String flag = getPropertyStringUnconditional(name);
        if (flag.equals("true")) return true;
        if (flag.equals("false")) return false;
        throw new IOException("Boolean syntax error: " + name);
    }

    public boolean hasProperty(String name) {
        return properties.getProperty(name) != null;
    }

    public String listProperties() {
        StringBuilder s = new StringBuilder();
        for (String key : properties.stringPropertyNames()) {
            if (s.length() > 0) {
                s.append(", ");
            }
            s.append(key).append('=').append(properties.getProperty(key));
        }
        return s.toString();
    }
}

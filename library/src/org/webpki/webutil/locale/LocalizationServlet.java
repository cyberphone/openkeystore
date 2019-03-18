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
package org.webpki.webutil.locale;

import java.io.IOException;

import javax.servlet.ServletContext;
import javax.servlet.http.HttpServlet;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLSchemaCache;

/**
 * <pre>
 * &lt;?xml version=&quot;1.0&quot; encoding=&quot;ISO-8859-1&quot;?&gt;
 * &lt;LocalizedStrings Language=&quot;US English&quot; Application=&quot;My demo app&quot;
 *                  xmlns=&quot;http://locale.com&quot;&gt;
 *   &lt;LString Name=&quot;welcome&quot;&gt;Welcome dear user!&lt;/LString&gt;
 *   &lt;LString Name=&quot;password&quot;&gt;Enter password:&lt;/LString&gt;
 *   &lt;LString Name=&quot;some_options&quot;&gt;Small,Medium,Big&lt;/LString&gt;
 * &lt;/LocalizedStrings&gt;</pre>
 */
public abstract class LocalizationServlet extends HttpServlet {

    private static final long serialVersionUID = 1L;  // Keep the compiler quite...

    protected abstract LocalizedStrings[] getStringConstants();

    protected static final String LOCALE_ATTRIBUTE = "L24578545885426";
    protected static final String LOCALEDATA_ATTRIBUTE = "LD24578545885426";


    protected String getLocale() throws IOException {
        return getLocale(getServletContext());
    }


    protected String getLocale(ServletContext context) throws IOException {
        String locale = (String) context.getAttribute(LOCALE_ATTRIBUTE);
        if (locale == null) {
            locale = context.getInitParameter("locale");
            if (locale == null) throw new IOException("No \"locale\" in web.xml");
        }
        context.setAttribute(LOCALE_ATTRIBUTE, locale);
        return locale;
    }

    protected LocalizedStringsSchema getLocalizationData(String locale, ServletContext context) throws IOException {
        XMLSchemaCache sc = new XMLSchemaCache();
        sc.addWrapper(LocalizedStringsSchema.class);
        return (LocalizedStringsSchema) sc.parse(ArrayUtil.readFile(
                context.getRealPath("/WEB-INF/locale/" + locale + "/locale.xml")));
    }


    protected String getLocalizedString(int sindex) throws IOException {
        ServletContext context = getServletContext();
        String localedata[] = (String[]) context.getAttribute(LOCALEDATA_ATTRIBUTE);
        if (localedata == null) {
            String locale = getLocale(context);
            LocalizedStringsSchema lss = getLocalizationData(locale, context);
            localedata = lss.getLocalizedStrings(getStringConstants());
            context.setAttribute(LOCALEDATA_ATTRIBUTE, localedata);
        }
        return localedata[sindex];
    }


    protected String[] getLocalizedStringSet(int sindex, int breakchar) throws IOException {
        String res = getLocalizedString(sindex);
        int i = 0;
        int j = 1;
        int k;
        while ((k = res.substring(i).indexOf(breakchar)) > 0) {
            j++;
            i += k + 1;
        }
        String[] sset = new String[j];
        i = 0;
        j = 0;
        while ((i = res.indexOf(breakchar)) > 0) {
            sset[j++] = res.substring(0, i++).trim();
            res = res.substring(i);
        }
        sset[j] = res.trim();
        return sset;
    }


    protected String[] getLocalizedStringSet(int sindex) throws IOException {
        return getLocalizedStringSet(sindex, ',');
    }

}

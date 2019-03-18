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

import java.util.Vector;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;

public class LocalizedStringsSchema extends XMLObjectWrapper {
    public void init() throws IOException {
        addSchema("localeschema.xsd");
    }


    protected boolean hasQualifiedElements() {
        return true;
    }


    public String namespace() {
        return "http://locale.com";
    }


    public String element() {
        return "LocalizedStrings";
    }

    private Vector<String> lsname = new Vector<String>();

    private Vector<String> lsvalue = new Vector<String>();

    private String language;

    private String application;


    public String getLanguage() {
        return language;
    }


    public String getApplication() {
        return application;
    }


    public String[] getLocalizedStrings(LocalizedStrings[] template) throws IOException {
        int l = lsvalue.size();
        if (template.length != l) {
            throw new IOException("Wrong number of elements in XML file");
        }

        int i = -1, max = 0;
        while (++i < template.length) {
            if (template[i].handle < 0 || template[i].handle > 9999) {
                throw new IOException("Index out localized string > 9999");
            }
            if (template[i].handle > max) {
                max = template[i].handle;
            }
        }
        String res[] = new String[max + 1];
        for (i = 0; i < l; i++) {
            int j = -1;
            boolean found = false;
            while (++j < l) {
                if (lsname.elementAt(j) != null && template[i].lsname.equals(lsname.elementAt(j))) {
                    if (res[template[i].handle] == null) {
                        res[template[i].handle] = lsvalue.elementAt(j);
                        lsname.setElementAt(null, j);
                        found = true;
                        break;
                    } else {
                        throw new IOException("Duplicate handle: " + template[i].lsname);
                    }
                }
            }
            if (!found) throw new IOException("Missing in XML file: " + template[i].lsname);
        }
        return res;
    }


    protected void fromXML(DOMReaderHelper rd) throws IOException {
        language = rd.getAttributeHelper().getString("Language");
        application = rd.getAttributeHelper().getString("Application");

        rd.getChild();

        while (rd.hasNext("LString")) {
            lsvalue.addElement(rd.getString());
            lsname.addElement(rd.getAttributeHelper().getString("Name"));
        }
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        throw new IOException("Not implemented (as it is not needed...)");
    }

}

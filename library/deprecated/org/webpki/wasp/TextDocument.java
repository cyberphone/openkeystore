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
package org.webpki.wasp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;

import org.webpki.xml.DOMWriterHelper;

import static org.webpki.wasp.WASPConstants.*;


public class TextDocument extends RootDocument {

    private boolean cdata_set;
    private boolean cdata;

    public void write(DOMWriterHelper wr) throws IOException {
        try {
            String value = new String(data, "UTF-8");
            int j = 0;
            int q = 0;
            while (j < data.length) {
                if (data[j++] == (byte) '<') {
                    q++;
                }
            }
            if (q > 5 || (cdata_set && cdata)) {
                if (value.indexOf('\r') >= 0) {
                    throw new IOException("DOS formatted text not allowed. Lines MUST end with \\n only");
                }
                wr.addCDATA(TEXT_SUB_ELEM, value);
            } else {
                wr.addString(TEXT_SUB_ELEM, value);
            }
            super.write(wr);
        } catch (UnsupportedEncodingException e) {
            throw new IOException(e.toString());
        }
    }


    public TextDocument(byte[] data, String content_id) {
        super.data = data;
        super.content_id = content_id;
    }


    public TextDocument(byte[] data, String content_id, boolean cdata) {
        super.data = data;
        super.content_id = content_id;
        this.cdata_set = true;
        this.cdata = cdata;
    }


    public boolean equals(RootDocument d) {
        return d instanceof TextDocument && dataEquality(d);
    }

}

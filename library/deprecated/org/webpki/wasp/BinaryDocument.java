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

import org.webpki.xml.DOMWriterHelper;

import static org.webpki.wasp.WASPConstants.*;


public class BinaryDocument extends RootDocument {

    public void write(DOMWriterHelper wr) throws IOException {
        wr.addBinary(BINARY_SUB_ELEM, data);
        super.write(wr);
    }


    public BinaryDocument(byte[] data, String content_id) {
        super.data = data;
        super.content_id = content_id;
    }


    public boolean equals(RootDocument d) {
        return d instanceof BinaryDocument && dataEquality(d);
    }

}

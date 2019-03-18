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


public class DeletedDocument extends RootDocument {
    String reason;

    public void write(DOMWriterHelper wr) throws IOException {
        wr.addEmptyElement(DELETED_SUB_ELEM);
        if (reason != null) {
            wr.setStringAttribute(REASON_ATTR, reason);
        }
        super.write(wr);
    }


    public DeletedDocument(String reason, String content_id) {
        super.content_id = content_id;
        this.reason = reason;
    }


    public String getReason() {
        return reason;
    }


    public boolean equals(RootDocument d) {
        return d instanceof DeletedDocument && content_id.equals(d.content_id) && reason.equals(((DeletedDocument) d).reason);
    }

}

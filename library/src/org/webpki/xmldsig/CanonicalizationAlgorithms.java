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
package org.webpki.xmldsig;

import java.io.IOException;


public enum CanonicalizationAlgorithms {
    C14N_INCL("http://www.w3.org/TR/2001/REC-xml-c14n-20010315"),
    C14N_INCL_WITH_COMMENTS("http://www.w3.org/TR/2001/REC-xml-c14n-20010315#WithComments"),
    C14N_EXCL("http://www.w3.org/2001/10/xml-exc-c14n#"),
    C14N_EXCL_WITH_COMMENTS("http://www.w3.org/2001/10/xml-exc-c14n#WithComments");

    private final String uri;       // As expressed in XML messages

    private CanonicalizationAlgorithms(String uri) {
        this.uri = uri;
    }


    public String getURI() {
        return uri;
    }


    public static boolean testAlgorithmURI(String uri) {
        for (CanonicalizationAlgorithms alg : values()) {
            if (uri.equals(alg.uri)) {
                return true;
            }
        }
        return false;
    }


    public static CanonicalizationAlgorithms getAlgorithmFromURI(String uri) throws IOException {
        for (CanonicalizationAlgorithms alg : values()) {
            if (uri.equals(alg.uri)) {
                return alg;
            }
        }
        throw new IOException("Unknown algorithm: " + uri);
    }

}

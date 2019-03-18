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

import java.security.GeneralSecurityException;
import java.security.cert.X509Certificate;

import java.util.Date;

import org.webpki.xml.XMLObjectWrapper;
import org.webpki.xml.DOMWriterHelper;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;


public class SignatureResponseEncoder extends SignatureResponse {

    private SignatureRequestDecoder sign_req_decoder;

    private SignatureProfileResponseEncoder sign_prof_resp_encoder;

    private boolean called_xml;
    private boolean called_sign;


    private String prefix;  // Default: no prefix


    private void check(boolean test, String error) throws IOException {
        if (test) throw new IOException(error);
    }


    public void setPrefix(String prefix) throws IOException {
        check(called_sign, "setPrefix MUST be called before createSignedResponse!");
        this.prefix = prefix;
    }


    public String getPrefix() {
        return prefix;
    }


    public void createSignedResponse(SignerInterface signer,
                                     SignatureRequestDecoder sign_req_decoder,
                                     SignatureProfileResponseEncoder sign_prof_resp_encoder,
                                     String requestUrl,
                                     Date clientTime,
                                     X509Certificate server_certificate) throws IOException {
        check(called_xml, "createSignedResponse MUST be called before XML generation!");
        called_sign = true;
        this.sign_req_decoder = sign_req_decoder;
        this.sign_prof_resp_encoder = sign_prof_resp_encoder;
        byte[] fingerprint = null;
        if (server_certificate != null) {
            try {
                fingerprint = HashAlgorithms.SHA256.digest(server_certificate.getEncoded());
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
        sign_prof_resp_encoder.createSignedData(signer,
                this,
                sign_req_decoder,
                requestUrl,
                clientTime,
                fingerprint);
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        check(!called_sign, "createSignedResponse not called!");
        called_xml = true;
        wr.initializeRootObject(prefix);
        wr.addWrapped((XMLObjectWrapper) sign_prof_resp_encoder);
        if (sign_req_decoder.getCopyData()) {
            sign_req_decoder.getDocumentData().write(wr);
        }
    }

}

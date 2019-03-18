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

import org.w3c.dom.Element;

import org.webpki.xml.DOMWriterHelper;

import org.webpki.xmldsig.XMLSigner;

import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.SignerInterface;

import static org.webpki.wasp.WASPConstants.*;


public class AuthenticationResponseEncoder extends AuthenticationResponse {
    private String serverTime;

    private Date clientTime;

    private boolean add_new_line = true;

    private String prefix;  // Default: no prefix


    public void setPrefix(String prefix) throws IOException {
        this.prefix = prefix;
    }


    public String getPrefix() {
        return prefix;
    }


    public void createSignedResponse(SignerInterface signer,
                                     AuthenticationRequestDecoder auth_req_decoder,
                                     String requestUrl,
                                     Date clientTime,
                                     X509Certificate server_certificate) throws IOException {
        this.id = auth_req_decoder.getID();
        this.serverTime = auth_req_decoder.getServerTime();
        this.requestUrl = requestUrl;
        this.submitUrl = auth_req_decoder.getSubmitUrl();
        this.clientTime = clientTime;
        if (server_certificate != null) {
            try {
                this.server_certificate_fingerprint = HashAlgorithms.SHA256.digest(server_certificate.getEncoded());
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }
        Element elem = forcedDOMRewrite();
        if (add_new_line) {
            elem.appendChild(getRootDocument().createTextNode("\n"));
        }

        AuthenticationProfile selected_auth_profile = auth_req_decoder.getAuthenticationProfiles()[0];
        XMLSigner ds = new XMLSigner(signer);
        ds.setSignatureAlgorithm(selected_auth_profile.getSignatureAlgorithm());
        ds.setDigestAlgorithm(selected_auth_profile.getDigestAlgorithm());
        ds.setTransformAlgorithm(selected_auth_profile.getCanonicalizationAlgorithm());
        ds.setCanonicalizationAlgorithm(selected_auth_profile.getCanonicalizationAlgorithm());
        ds.setSignedKeyInfo(selected_auth_profile.getSignedKeyInfo());

        ds.createEnvelopedSignature(getRootDocument(), id);
    }


    public AuthenticationResponseEncoder addClientPlatformFeature(ClientPlatformFeature client_platform_feature) {
        client_platform_features.add(client_platform_feature);
        return this;
    }


    protected void toXML(DOMWriterHelper wr) throws IOException {
        wr.initializeRootObject(prefix);

        wr.setStringAttribute(ID_ATTR, id);

        wr.setStringAttribute(SERVER_TIME_ATTR, serverTime);

        wr.setStringAttribute(SUBMIT_URL_ATTR, submitUrl);

        wr.setStringAttribute(REQUEST_URL_ATTR, requestUrl);

        wr.setDateTimeAttribute(CLIENT_TIME_ATTR, clientTime);

        if (server_certificate_fingerprint != null) {
            wr.setBinaryAttribute(SERVER_CERT_FP_ATTR, server_certificate_fingerprint);
        }

        for (ClientPlatformFeature client_platform_feature : client_platform_features) {
            add_new_line = false;
            client_platform_feature.write(wr);
        }
    }
}

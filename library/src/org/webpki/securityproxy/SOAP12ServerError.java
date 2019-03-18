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

/**
 * Sample factory for returning internal security proxy errors in SOAP 1.2 format.
 */
public class SOAP12ServerError extends ProxyServerErrorFactory {
    static final String SOAP12_MIME = "application/soap+xml; charset=\"utf-8\"";

    public byte[] getContent() throws IOException {
        return ("<?xml version=\"1.0\" encoding=\"UTF-8\"?>" +
                "<soap12:Envelope xmlns:soap12=\"http://www.w3.org/2003/05/soap-envelope\">" +
                "<soap12:Body>" +
                "<soap12:Fault>" +
                "<soap12:Code>" +
                "<soap12:Value>soap12:Receiver</soap12:Value>" +
                "</soap12:Code>" +
                "<soap12:Reason>" +
                "<soap12:Text xml:lang=\"en\">" + message + "</soap12:Text>" +
                "</soap12:Reason>" +
                "</soap12:Fault>" +
                "</soap12:Body>" +
                "</soap12:Envelope>").getBytes("UTF-8");
    }

    public String getMimeType() {
        return SOAP12_MIME;
    }
}

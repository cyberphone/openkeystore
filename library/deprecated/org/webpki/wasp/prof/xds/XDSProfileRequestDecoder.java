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
package org.webpki.wasp.prof.xds;

import java.io.IOException;

import org.webpki.xml.DOMReaderHelper;
import org.webpki.xml.DOMWriterHelper;
import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.XMLObjectWrapper;
import org.webpki.wasp.SignatureProfileDecoder;
import org.webpki.wasp.SignatureProfileResponseEncoder;
import org.webpki.xmldsig.CanonicalizationAlgorithms;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.HashAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import static org.webpki.wasp.WASPConstants.*;
import static org.webpki.wasp.prof.xds.XDSProfileConstants.*;


public class XDSProfileRequestDecoder extends XMLObjectWrapper implements SignatureProfileDecoder {

    private boolean signed_key_info;

    private boolean extendedCertPath;

    private String canonicalization_algorithm;

    private String digest_algorithm;

    private String signatureAlgorithm;

    private String document_canonicalization_algorithm;


    protected boolean hasQualifiedElements() {
        return true;
    }


    public void init() throws IOException {
        addSchema(XML_SCHEMA_FILE);
    }


    public String namespace() {
        return XML_SCHEMA_NAMESPACE;
    }


    public String element() {
        return REQUEST_ELEM;
    }


    public boolean getSignedKeyInfo() {
        return signed_key_info;
    }


    public boolean getExtendedCertPath() {
        return extendedCertPath;
    }


    public CanonicalizationAlgorithms getCanonicalizationAlgorithm() throws IOException {
        return canonicalization_algorithm == null ? null : CanonicalizationAlgorithms.getAlgorithmFromURI(canonicalization_algorithm);
    }


    public HashAlgorithms getDigestAlgorithm() throws IOException {
        return digest_algorithm == null ? null : HashAlgorithms.getAlgorithmFromID(digest_algorithm);
    }


    public AsymSignatureAlgorithms getSignatureAlgorithm() throws IOException {
        return signatureAlgorithm == null ? null : AsymSignatureAlgorithms.getAlgorithmFromID(signatureAlgorithm,
                AlgorithmPreferences.SKS);
    }


    public String getDocumentCanonicalizationAlgorithm() {
        return document_canonicalization_algorithm;
    }

    /////////////////////////////////////////////////////////////////////////////////////////////
    // XML Reader
    /////////////////////////////////////////////////////////////////////////////////////////////

    protected void fromXML(DOMReaderHelper rd) throws IOException {
        DOMAttributeReaderHelper ah = rd.getAttributeHelper();
        //////////////////////////////////////////////////////////////////////////
        // Get the top-level attributes (which is all this profile has...)
        //////////////////////////////////////////////////////////////////////////
        signed_key_info = ah.getBooleanConditional(SIGNED_KEY_INFO_ATTR);

        extendedCertPath = ah.getBooleanConditional(EXTENDED_CERT_PATH_ATTR);

        canonicalization_algorithm = ah.getStringConditional(CN_ALG_ATTR);

        digest_algorithm = ah.getStringConditional(DIGEST_ALG_ATTR);

        signatureAlgorithm = ah.getStringConditional(SIGNATURE_ALG_ATTR);

        document_canonicalization_algorithm = ah.getStringConditional(DOC_CN_ALG_ATTR, DOC_SIGN_CN_ALG);
    }

    protected void toXML(DOMWriterHelper helper) throws IOException {
        throw new IOException("Should NEVER be called");
    }

    public SignatureProfileResponseEncoder createSignatureProfileResponseEncoder() {
        return new XDSProfileResponseEncoder(this);
    }


    public boolean hasSupportedParameters() {
        return (canonicalization_algorithm == null || CanonicalizationAlgorithms.testAlgorithmURI(canonicalization_algorithm)) &&
                (digest_algorithm == null || HashAlgorithms.testAlgorithmURI(digest_algorithm)) &&
                (signatureAlgorithm == null || AsymSignatureAlgorithms.testAlgorithmURI(signatureAlgorithm)) &&
                document_canonicalization_algorithm.equals(DOC_SIGN_CN_ALG);
    }

}

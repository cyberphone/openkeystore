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

import java.security.PublicKey;
import java.security.GeneralSecurityException;

import java.util.logging.Logger;

import org.w3c.dom.Node;
import org.w3c.dom.Element;

import org.webpki.util.ArrayUtil;

import org.webpki.xml.XMLObjectWrapper;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.HashAlgorithms;


abstract class XMLVerifierCore {
    private static Logger logger = Logger.getLogger(XMLVerifierCore.class.getCanonicalName());

    private SignedKeyInfoSpecifier KeyInfo_requirements = SignedKeyInfoSpecifier.FORBID_SIGNED_KEY_INFO;

    private HashAlgorithms digest_algorithm;  // Only tested for main Reference not for keyinfo types

    private AsymSignatureAlgorithms signatureAlgorithm;

    private boolean debug;


    public void setDebug(boolean flag) {
        debug = flag;
    }


    private void checkReference(XMLSignatureWrapper.ReferenceObject ref) throws IOException, GeneralSecurityException {
        byte[] ref_cn = XPathCanonicalizer.serializeSubset(ref.element, ref.cn_alg);
        if (debug) {
            logger.info(ref.id + "=\n" + new String(ref_cn));
        }
        if (!ArrayUtil.compare(ref.digestAlg.digest(ref_cn), ref.digest_val)) {
            throw new IOException("Incorrect message digest id=" + ref.id);
        }
    }


    abstract void verify(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException;


    private void checkMainReference(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException {
        // Check the mandatory Object/Outer container reference
        digest_algorithm = signature.reference_object_1.digestAlg;
        checkReference(signature.reference_object_1);
    }


    private void checkKeyInfoReference(XMLSignatureWrapper signature) throws IOException, GeneralSecurityException {
        // Check the optional KeyInfo reference
        if (signature.reference_object_2 == null) {
            if (KeyInfo_requirements == SignedKeyInfoSpecifier.REQUIRE_SIGNED_KEY_INFO) {
                throw new IOException("KeyInfo Reference mode = REQUIRED");
            }
        } else {
            if (KeyInfo_requirements == SignedKeyInfoSpecifier.FORBID_SIGNED_KEY_INFO) {
                throw new IOException("KeyInfo Reference mode = FORBIDDEN");
            }
            checkReference(signature.reference_object_2);
        }
    }


    void core_verify(XMLSignatureWrapper signature, PublicKey publicKey) throws IOException, GeneralSecurityException {
        byte[] sign_cn = XPathCanonicalizer.serializeSubset(signature.signedinfo_object.element, signature.signedinfo_object.cn_alg);
        if (debug) {
            logger.info(XMLSignatureWrapper.SIGNED_INFO_ELEM + "=\n" + new String(sign_cn));
        }
        boolean success;
        if (this instanceof XMLSymKeyVerifier) {
            success = ((XMLSymKeyVerifier) this).
                    sym_verifier.verifyData(sign_cn,
                    signature.signedinfo_object.signature_val,
                    signature.signedinfo_object.sym_signature_alg,
                    signature.symmetric_key_name);
        } else {
            // Check signature
            signatureAlgorithm = signature.signedinfo_object.asym_signature_alg;
            success = new SignatureWrapper(signature.signedinfo_object.asym_signature_alg, publicKey)
                    .update(sign_cn)
                    .verify(signature.signedinfo_object.signature_val);
        }
        if (!success) {
            throw new IOException("Incorrect signature for element: " + signature.reference_object_1.element.getNodeName());
        }
    }


    /**
     * Verifies a signed message and returns the signed data.
     *
     * @param message The enveloping signed XML object.
     * @return the original XML object.
     * @throws IOException If anything unexpected happens...
     */
    public XMLObjectWrapper verifyXMLWrapper(XMLSignatureWrapper message) throws IOException {
        if (message.wrappedData == null) {
            throw new IOException("Message data not wrapped.");
        }
        try {
            checkMainReference(message);
            checkKeyInfoReference(message);
            verify(message);
        } catch (GeneralSecurityException gse) {
            throw new IOException(gse.getMessage());
        }

        return message.wrappedData;
    }


    public void setSignedKeyInfo(SignedKeyInfoSpecifier keyinforeq) {
        KeyInfo_requirements = keyinforeq;
    }


    public AsymSignatureAlgorithms getSignatureAlgorithm() {
        return signatureAlgorithm;
    }


    public HashAlgorithms getDigestAlgorithm() {
        return digest_algorithm;
    }


    /**
     * Verifies an enveloped signed message and returns the signed data.
     *
     * @param parent    The enveloped signed XML object.
     * @param element   The actual element (null implies root).
     * @param signature The enveloped signature.
     * @param id        The mandatory ID element.
     * @return XML document "as-is").
     * @throws IOException If anything unexpected happens...
     */
    public XMLObjectWrapper validateEnvelopedSignature(XMLObjectWrapper parent,
                                                       Element element,
                                                       XMLSignatureWrapper signature,
                                                       String id) throws IOException {
        if (!signature.reference_object_1.enveloped) {
            throw new IOException("Expected enveloped signature");
        }
        if (!signature.reference_object_1.id.equals(id)) {
            throw new IOException("Id mismatch (" + signature.reference_object_1.id + ", " + id + ").");
        }

        try {
            signature.reference_object_1.element = element == null ? parent.getRootElement() : element;
            checkKeyInfoReference(signature);
            Node signsin = signature.getRootElement().getNextSibling();
            Node signpar = signature.getRootElement().getParentNode();
            signpar.removeChild(signature.getRootElement());
            checkMainReference(signature);
            signpar.insertBefore(signature.getRootElement(), signsin);
            verify(signature);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
        return parent;
    }


    /**
     * Verifies an enveloped signed message.
     *
     * @param parent The enveloped signed XML object.
     * @return "parent" as is.
     * @throws IOException If anything unexpected happens...
     */
    public XMLObjectWrapper validateEnvelopedSignature(XMLObjectWrapper parent) throws IOException {
        if (!(parent instanceof XMLEnvelopedInput)) {
            throw new IOException("Must be an instance of XMLEnvelopedInput");
        }
        XMLEnvelopedInput xei = (XMLEnvelopedInput) parent;
        return validateEnvelopedSignature(parent, xei.getTargetElem(), xei.getSignature(), xei.getReferenceURI());
    }

}

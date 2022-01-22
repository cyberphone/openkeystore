/*
 *  Copyright 2018-2020 WebPKI.org (http://webpki.org).
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
package org.webpki.webapps.csf_lab;

import java.io.IOException;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.PublicKey;

import java.util.logging.Level;
import java.util.logging.Logger;

import javax.servlet.ServletContextEvent;
import javax.servlet.ServletContextListener;

import org.webpki.cbor.CBORAsymKeyValidator;
import org.webpki.cbor.CBORMap;
import org.webpki.cbor.CBORObject;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.SignatureAlgorithms;

import org.webpki.util.ArrayUtil;

import org.webpki.webutil.InitPropertyReader;

public class CSFService extends InitPropertyReader implements ServletContextListener {

    static Logger logger = Logger.getLogger(CSFService.class.getName());

    static String sampleSignature;
    
    static String sampleLabel;
    
    static String samplePublicKey;
    
    static String keyDeclarations;
    
    static boolean logging;

    class KeyDeclaration {
        
        static final String PRIVATE_KEYS = "privateKeys";
        static final String SECRET_KEYS  = "secretKeys";
        static final String CERTIFICATES = "certifictes";
        
        StringBuilder decl = new StringBuilder("var ");
        StringBuilder after = new StringBuilder();
        String name;
        String last;
        String base;
        
        KeyDeclaration(String name, String base) {
            this.name = name;
            this.base = base;
            decl.append(name)
                .append(" = {");
        }

        KeyDeclaration addKey(SignatureAlgorithms alg, String fileOrNull) throws IOException {
            String algId = alg.getAlgorithmId(AlgorithmPreferences.JOSE);
            if (fileOrNull == null) {
                after.append(name)
                     .append('.')
                     .append(algId)
                     .append(" = ")
                     .append(name)
                     .append('.')
                     .append(last)
                     .append(";\n");
                     
            } else {
                if (last != null) {
                    decl.append(',');
                }
                decl.append("\n    ")
                    .append(algId)
                    .append(": '")
                    .append(HTML.javaScript(getEmbeddedResourceString(fileOrNull + base).trim()))
                    .append('\'');
                last = algId;
            }
            return this;
        }
        
        public String toString() {
            return decl.append("\n};\n").append(after).toString();
        }
    }

    byte[] getEmbeddedResource(String name) throws IOException {
        InputStream is = this.getClass().getResourceAsStream(name);
        if (is == null) {
            throw new IOException("Resource fail for: " + name);
        }
        return ArrayUtil.getByteArrayFromInputStream(is);
    }
    
    String getEmbeddedResourceString(String name) throws IOException {
        return new String(getEmbeddedResource(name), "utf-8");
    }

    @Override
    public void contextDestroyed(ServletContextEvent event) {
    }

    @Override
    public void contextInitialized(ServletContextEvent event) {
        initProperties(event);
        CustomCryptoProvider.forcedLoad(false);
        try {
            /////////////////////////////////////////////////////////////////////////////////////////////
            // Keys
            /////////////////////////////////////////////////////////////////////////////////////////////
            keyDeclarations = 
                    new KeyDeclaration(KeyDeclaration.PRIVATE_KEYS, "privatekey.pem")
                          .addKey(AsymSignatureAlgorithms.ED25519,       "ed25519")
                          .addKey(AsymSignatureAlgorithms.ED448,         "ed448")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA256,  "p256")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA384,  "p384")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA512,  "p521")
                          .addKey(AsymSignatureAlgorithms.RSA_SHA256,    "r2048")
                          .addKey(AsymSignatureAlgorithms.RSA_SHA384,    null)
                          .addKey(AsymSignatureAlgorithms.RSA_SHA512,    null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA256, null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA384, null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA512, null).toString() +
                    new KeyDeclaration(KeyDeclaration.CERTIFICATES, "certpath.pem")
                          .addKey(AsymSignatureAlgorithms.ED25519,       "ed25519")
                          .addKey(AsymSignatureAlgorithms.ED448,         "ed448")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA256,  "p256")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA384,  "p384")
                          .addKey(AsymSignatureAlgorithms.ECDSA_SHA512,  "p521")
                          .addKey(AsymSignatureAlgorithms.RSA_SHA256,    "r2048")
                          .addKey(AsymSignatureAlgorithms.RSA_SHA384,    null)
                          .addKey(AsymSignatureAlgorithms.RSA_SHA512,    null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA256, null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA384, null)
                          .addKey(AsymSignatureAlgorithms.RSAPSS_SHA512, null).toString() +
                    new KeyDeclaration(KeyDeclaration.SECRET_KEYS, "bitkey.hex")
                          .addKey(HmacAlgorithms.HMAC_SHA256,            "a256")
                          .addKey(HmacAlgorithms.HMAC_SHA384,            "a384")
                          .addKey(HmacAlgorithms.HMAC_SHA512,            "a512").toString();

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Sample signature for verification
            /////////////////////////////////////////////////////////////////////////////////////////////
            CBORMap demoSignature = 
                    CBORObject.decode(getEmbeddedResource("demo-doc-signature.cbor")).getMap();
            CBORObject[] keys = demoSignature.getKeys();
            CBORObject signatureLabel = keys[keys.length - 1];
            sampleLabel = signatureLabel.toString();
            sampleSignature = demoSignature.toString();
            samplePublicKey = getEmbeddedResourceString("p256publickey.pem").trim();
            new CBORAsymKeyValidator(new CBORAsymKeyValidator.KeyLocator() {

                @Override
                public PublicKey locate(PublicKey publicKey, 
                                        CBORObject keyId, 
                                        AsymSignatureAlgorithms algorithm)
                        throws IOException, GeneralSecurityException {
                    if (publicKey == null) {
                        throw new GeneralSecurityException("No public key");
                    }
                    return publicKey;
                }
                
            }).validate(signatureLabel, demoSignature);

            /////////////////////////////////////////////////////////////////////////////////////////////
            // Logging?
            /////////////////////////////////////////////////////////////////////////////////////////////
            logging = getPropertyBoolean("logging");

            logger.info("CSF Lab Successfully Initiated");
        } catch (Exception e) {
            logger.log(Level.SEVERE, "********\n" + e.getMessage() + "\n********", e);
        }
    }
}

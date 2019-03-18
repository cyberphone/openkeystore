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
package org.webpki.keygen2;

import java.io.IOException;

import java.util.Vector;

import java.security.cert.X509Certificate;

import org.webpki.sks.SecureKeyStore;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.CertificateFilter;

import org.webpki.json.JSONArrayReader;
import org.webpki.json.JSONObjectReader;

import static org.webpki.keygen2.KeyGen2Constants.*;

public class ProvisioningFinalizationRequestDecoder extends ClientDecoder {

    private static final long serialVersionUID = 1L;

    public class PostOperation {

        public static final int DELETE_KEY           = 0;
        public static final int UNLOCK_KEY           = 1;
        public static final int UPDATE_KEY           = 2;
        public static final int CLONE_KEY_PROTECTION = 3;

        String clientSessionId;

        String serverSessionId;

        byte[] mac;

        byte[] certificateFingerprint;

        byte[] authorization;

        int postOperation;

        PostOperation(String clientSessionId,
                      String serverSessionId,
                      byte[] certificateFingerprint,
                      byte[] authorization,
                      byte[] mac,
                      int postOperation) {
            this.clientSessionId = clientSessionId;
            this.serverSessionId = serverSessionId;
            this.certificateFingerprint = certificateFingerprint;
            this.authorization = authorization;
            this.mac = mac;
            this.postOperation = postOperation;
        }

        public byte[] getMac() {
            return mac;
        }

        public byte[] getCertificateFingerprint() {
            return certificateFingerprint;
        }

        public byte[] getAuthorization() {
            return authorization;
        }

        public int getPostOperation() {
            return postOperation;
        }

        public String getClientSessionId() {
            return clientSessionId;
        }

        public String getServerSessionId() {
            return serverSessionId;
        }

    }

    public abstract class Extension {

        String type;

        public String getExtensionType() {
            return type;
        }

        byte[] mac;

        public byte[] getMac() {
            return mac;
        }

        public abstract byte getSubType();

        public String getQualifier() throws IOException {
            return "";
        }

        public abstract byte[] getExtensionData() throws IOException;

        Extension(JSONObjectReader rd, IssuedCredential cpk) throws IOException {
            type = rd.getString(TYPE_JSON);
            mac = KeyGen2Validator.getMac(rd);
            cpk.extensions.add(this);
        }
    }


    class StandardExtension extends Extension {

        byte[] data;

        StandardExtension(JSONObjectReader rd, IssuedCredential cpk) throws IOException {
            super(rd, cpk);
            data = rd.getBinary(EXTENSION_DATA_JSON);
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_EXTENSION;
        }


        @Override
        public byte[] getExtensionData() throws IOException {
            return data;
        }
    }


    class EncryptedExtension extends Extension {

        byte[] data;

        EncryptedExtension(JSONObjectReader rd, IssuedCredential cpk) throws IOException {
            super(rd, cpk);
            this.data = rd.getBinary(EXTENSION_DATA_JSON);
        }


        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION;
        }


        @Override
        public byte[] getExtensionData() throws IOException {
            return data;
        }
    }


    class Property {

        private Property() {}

        String name;

        String value;

        boolean writable;
    }


    class PropertyBag extends Extension {

        Vector<Property> properties = new Vector<Property>();

        PropertyBag(JSONObjectReader rd, IssuedCredential cpk) throws IOException {
            super(rd, cpk);
            JSONArrayReader props = rd.getArray(PROPERTIES_JSON);
            do {
                JSONObjectReader propertyReader = props.getObject();
                Property property = new Property();
                property.name = propertyReader.getString(NAME_JSON);
                property.value = propertyReader.getString(VALUE_JSON);
                property.writable = propertyReader.getBooleanConditional(WRITABLE_JSON);
                properties.add(property);
            } while (props.hasMore());
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_PROPERTY_BAG;
        }


        private byte[] getStringData(String string) throws IOException {
            byte[] data = string.getBytes("UTF-8");
            return ArrayUtil.add(new byte[]{(byte) (data.length >>> 8), (byte) data.length}, data);
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            byte[] total = new byte[0];
            for (Property property : properties) {
                total = ArrayUtil.add(total,
                                      ArrayUtil.add(getStringData(property.name),
                                                    ArrayUtil.add(new byte[]{property.writable ? (byte) 1 : (byte) 0},
                                                                  getStringData(property.value))));
            }
            return total;
        }
    }


    class Logotype extends Extension {

        byte[] data;

        String mimeType;

        Logotype(JSONObjectReader rd, IssuedCredential cpk) throws IOException {
            super(rd, cpk);
            mimeType = rd.getString(MIME_TYPE_JSON);
            data = rd.getBinary(EXTENSION_DATA_JSON);
        }

        @Override
        public byte getSubType() {
            return SecureKeyStore.SUB_TYPE_LOGOTYPE;
        }

        @Override
        public String getQualifier() {
            return mimeType;
        }

        @Override
        public byte[] getExtensionData() throws IOException {
            return data;
        }
    }


    public class IssuedCredential {

        X509Certificate[] certificatePath;

        String id;

        byte[] encryptedSymmetricKey;

        byte[] symmetricKeyMac;

        byte[] encryptedPrivateKey;

        byte[] privateKeyMac;

        byte[] mac;

        boolean trustAnchor;

        Vector<Extension> extensions = new Vector<Extension>();

        PostOperation postOperation;

        IssuedCredential() {
        }


        IssuedCredential(JSONObjectReader rd) throws IOException {
            id = rd.getString(ID_JSON);
            certificatePath = rd.getCertificatePath();
            mac = KeyGen2Validator.getMac(rd);

            trustAnchor = rd.getBooleanConditional(TRUST_ANCHOR_JSON);
            if (trustAnchor) {
                if (certificatePath[certificatePath.length - 1].getBasicConstraints() < 0) {
                    throw new IOException("The \"" + TRUST_ANCHOR_JSON + "\" option requires a CA certificate");
                }
            }

            if (rd.hasProperty(IMPORT_SYMMETRIC_KEY_JSON)) {
                JSONObjectReader import_key = rd.getObject(IMPORT_SYMMETRIC_KEY_JSON);
                encryptedSymmetricKey = import_key.getBinary(ENCRYPTED_KEY_JSON);
                symmetricKeyMac = KeyGen2Validator.getMac(import_key);
            } else if (rd.hasProperty(IMPORT_PRIVATE_KEY_JSON)) {
                JSONObjectReader import_key = rd.getObject(IMPORT_PRIVATE_KEY_JSON);
                encryptedPrivateKey = import_key.getBinary(ENCRYPTED_KEY_JSON);
                privateKeyMac = KeyGen2Validator.getMac(import_key);
            }

            for (JSONObjectReader extension : getObjectArrayConditional(rd, EXTENSIONS_JSON)) {
                new StandardExtension(extension, this);
            }

            for (JSONObjectReader encryptedExtension : getObjectArrayConditional(rd, ENCRYPTED_EXTENSIONS_JSON)) {
                new EncryptedExtension(encryptedExtension, this);
            }

            for (JSONObjectReader propertyBag : getObjectArrayConditional(rd, PROPERTY_BAGS_JSON)) {
                new PropertyBag(propertyBag, this);
            }

            for (JSONObjectReader logotype : getObjectArrayConditional(rd, LOGOTYPES_JSON)) {
                new Logotype(logotype, this);
            }

            if (rd.hasProperty(CLONE_KEY_PROTECTION_JSON)) {
                postOperation = readPostOperation(rd.getObject(CLONE_KEY_PROTECTION_JSON), PostOperation.CLONE_KEY_PROTECTION);
            } else if (rd.hasProperty(UPDATE_KEY_JSON)) {
                postOperation = readPostOperation(rd.getObject(UPDATE_KEY_JSON), PostOperation.UPDATE_KEY);
            }
        }


        public X509Certificate[] getCertificatePath() {
            return certificatePath;
        }


        public byte[] getOptionalSymmetricKey() {
            return encryptedSymmetricKey;
        }


        public byte[] getSymmetricKeyMac() {
            return symmetricKeyMac;
        }


        public byte[] getOptionalPrivateKey() {
            return encryptedPrivateKey;
        }


        public byte[] getPrivateKeyMac() {
            return privateKeyMac;
        }


        public String getId() {
            return id;
        }

        public byte[] getMac() {
            return mac;
        }


        public Extension[] getExtensions() {
            return extensions.toArray(new Extension[0]);
        }

        public PostOperation getPostOperation() {
            return postOperation;
        }

        public boolean getTrustAnchorFlag() {
            return trustAnchor;
        }

    }

    private PostOperation readPostOperation(JSONObjectReader rd, int postOp) throws IOException {
        return new PostOperation(KeyGen2Validator.getID(rd, CLIENT_SESSION_ID_JSON),
                                 KeyGen2Validator.getID(rd, SERVER_SESSION_ID_JSON),
                                 rd.getBinary(CertificateFilter.CF_FINGER_PRINT),
                                 rd.getBinary(AUTHORIZATION_JSON),
                                 KeyGen2Validator.getMac(rd),
                                 postOp);
    }

    private Vector<IssuedCredential> issuedKeys = new Vector<IssuedCredential>();

    private Vector<PostOperation> postUnlockKeys = new Vector<PostOperation>();

    private Vector<PostOperation> postDeleteKeys = new Vector<PostOperation>();

    private String clientSessionId;

    private String serverSessionId;

    private String submitUrl;

    private byte[] closeSessionMac;

    private byte[] closeSessionNonce;


    public String getServerSessionId() {
        return serverSessionId;
    }


    public String getClientSessionId() {
        return clientSessionId;
    }


    public String getSubmitUrl() {
        return submitUrl;
    }


    public IssuedCredential[] getIssuedCredentials() {
        return issuedKeys.toArray(new IssuedCredential[0]);
    }


    public PostOperation[] getPostUnlockKeys() {
        return postUnlockKeys.toArray(new PostOperation[0]);
    }


    public PostOperation[] getPostDeleteKeys() {
        return postDeleteKeys.toArray(new PostOperation[0]);
    }


    public byte[] getCloseSessionMac() {
        return closeSessionMac;
    }


    public byte[] getCloseSessionNonce() {
        return closeSessionNonce;
    }


    @Override
    void readServerRequest(JSONObjectReader rd) throws IOException {
        /////////////////////////////////////////////////////////////////////////////////////////
        // Session properties
        /////////////////////////////////////////////////////////////////////////////////////////
        serverSessionId = getID(rd, SERVER_SESSION_ID_JSON);

        clientSessionId = getID(rd, CLIENT_SESSION_ID_JSON);

        closeSessionNonce = rd.getBinary(NONCE_JSON);

        closeSessionMac = KeyGen2Validator.getMac(rd);

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get the issued_keys [0..n]
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional(rd, ISSUED_CREDENTIALS_JSON)) {
            issuedKeys.add(new IssuedCredential(keys));
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning unlocks
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional(rd, UNLOCK_KEYS_JSON)) {
            postUnlockKeys.add(readPostOperation(keys, PostOperation.UNLOCK_KEY));
        }

        /////////////////////////////////////////////////////////////////////////////////////////
        // Get optional post provisioning deletes
        /////////////////////////////////////////////////////////////////////////////////////////
        for (JSONObjectReader keys : getObjectArrayConditional(rd, DELETE_KEYS_JSON)) {
            postDeleteKeys.add(readPostOperation(keys, PostOperation.DELETE_KEY));
        }
    }

    @Override
    public String getQualifier() {
        return KeyGen2Messages.PROVISIONING_FINALIZATION_REQUEST.getName();
    }
}

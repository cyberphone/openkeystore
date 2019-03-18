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
package org.webpki.sks;

import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.GregorianCalendar;

import org.webpki.asn1.cert.DistinguishedName;
import org.webpki.ca.CA;
import org.webpki.ca.CertSpec;
import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.sks.EnumeratedKey;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.ProvSess.MacGenerator;
import org.webpki.util.ArrayUtil;

public class GenKey {
    public String id;
    public int keyHandle;
    PublicKey publicKey;
    X509Certificate[] cert_path;
    ProvSess prov_sess;

    static long serialNumber = 10000;

    public GenKey setCertificate(int length) throws IOException, GeneralSecurityException {
        StringBuilder dn = new StringBuilder("CN=");
        for (int i = 1; i < length; i++) {
            if (i % 64 == 0) {
                dn.append(",CN=");
            }
            dn.append('Y');
        }
        return setCertificate(dn.toString(), publicKey);
    }

    public GenKey setCertificate(String dn) throws IOException, GeneralSecurityException {
        return setCertificate(dn, publicKey);
    }

    public GenKey setCertificate(String dn, PublicKey publicKey) throws IOException, GeneralSecurityException {
        CertSpec cert_spec = new CertSpec();
        cert_spec.setEndEntityConstraint();
        cert_spec.setSubject(dn);

        GregorianCalendar start = new GregorianCalendar();
        GregorianCalendar end = (GregorianCalendar) start.clone();
        end.set(GregorianCalendar.YEAR, end.get(GregorianCalendar.YEAR) + 25);

        X509Certificate certificate =
                new CA().createCert(cert_spec,
                        DistinguishedName.subjectDN((X509Certificate) DemoKeyStore.getSubCAKeyStore().getCertificate("mykey")),
                        BigInteger.valueOf(serialNumber++).shiftLeft(64).add(BigInteger.valueOf(new GregorianCalendar().getTimeInMillis())),
                        start.getTime(),
                        end.getTime(),
                        AsymSignatureAlgorithms.RSA_SHA256,
                        new AsymKeySignerInterface() {

                            @Override
                            public PublicKey getPublicKey() throws IOException {
                                try {
                                    return ((X509Certificate) DemoKeyStore.getSubCAKeyStore().getCertificate("mykey")).getPublicKey();
                                } catch (GeneralSecurityException e) {
                                    throw new IOException(e);
                                }
                            }

                            @Override
                            public byte[] signData(byte[] data, AsymSignatureAlgorithms algorithm) throws IOException {
                                try {
                                    SignatureWrapper signer = new SignatureWrapper(algorithm,
                                            (PrivateKey) DemoKeyStore.getSubCAKeyStore()
                                                    .getKey("mykey", DemoKeyStore.getSignerPassword().toCharArray()));
                                    signer.setEcdsaSignatureEncoding(true);
                                    signer.update(data);
                                    return signer.sign();
                                } catch (GeneralSecurityException e) {
                                    throw new IOException(e);
                                }

                            }

                        }, publicKey);
        return setCertificatePath(new X509Certificate[]{certificate});
    }

    public GenKey setCertificatePath(X509Certificate[] cert_path) throws IOException, GeneralSecurityException {
        this.cert_path = cert_path;
        prov_sess.setCertificate(keyHandle, id, publicKey, cert_path);
        return this;
    }

    public PublicKey getPublicKey() {
        return cert_path == null ? publicKey : cert_path[0].getPublicKey();
    }

    public X509Certificate[] getCertificatePath() {
        return cert_path;
    }

    public void setSymmetricKey(byte[] symmetricKey) throws IOException, GeneralSecurityException {
        MacGenerator symk_mac = getEECertMacBuilder();
        byte[] encrypted_symmetric_key = prov_sess.server_sess_key.encrypt(symmetricKey);
        symk_mac.addArray(encrypted_symmetric_key);
        prov_sess.sks.importSymmetricKey(keyHandle, encrypted_symmetric_key, prov_sess.mac4call(symk_mac.getResult(), SecureKeyStore.METHOD_IMPORT_SYMMETRIC_KEY));
    }

    public void setPrivateKey(PrivateKey privateKey) throws IOException, GeneralSecurityException {
        MacGenerator privk_mac = getEECertMacBuilder();
        byte[] encrypted_private_key = prov_sess.server_sess_key.encrypt(privateKey.getEncoded());
        privk_mac.addArray(encrypted_private_key);
        prov_sess.sks.importPrivateKey(keyHandle, encrypted_private_key, prov_sess.mac4call(privk_mac.getResult(), SecureKeyStore.METHOD_IMPORT_PRIVATE_KEY));
    }

    public void addExtension(String type, byte subType, String qualifier, byte[] extension_data) throws IOException, GeneralSecurityException {
        MacGenerator ext_mac = getEECertMacBuilder();
        if (subType == SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION) {
            extension_data = prov_sess.server_sess_key.encrypt(extension_data);
        }
        ext_mac.addString(type);
        ext_mac.addByte(subType);
        ext_mac.addString(qualifier);
        ext_mac.addBlob(extension_data);
        prov_sess.sks.addExtension(keyHandle, type, subType, qualifier, extension_data, prov_sess.mac4call(ext_mac.getResult(), SecureKeyStore.METHOD_ADD_EXTENSION));
    }

    public byte[] getPostProvMac(MacGenerator upd_mac, ProvSess current) throws IOException, GeneralSecurityException {
        Integer kmk_id = current.kmk_id;
        if (kmk_id == null) {
            kmk_id = 0;  // Just for JUnit...
        }
        PublicKey kmk = current.server_sess_key.enumerateKeyManagementKeys()[kmk_id];
        byte[] authorization = current.server_sess_key.generateKeyManagementAuthorization(kmk,
                ArrayUtil.add(SecureKeyStore.KMK_TARGET_KEY_REFERENCE,
                        current.mac(cert_path[0].getEncoded(),
                                current.getDeviceID())));
        upd_mac.addArray(authorization);
        return authorization;
    }

    ProvSess.MacGenerator getEECertMacBuilder() throws CertificateEncodingException, IOException {
        ProvSess.MacGenerator ee_mac = new ProvSess.MacGenerator();
        ee_mac.addArray(cert_path[0].getEncoded());
        return ee_mac;
    }

    public boolean exists() throws SKSException {
        EnumeratedKey ek = new EnumeratedKey();
        while ((ek = prov_sess.sks.enumerateKeys(ek.getKeyHandle())) != null) {
            if (ek.getKeyHandle() == keyHandle) {
                return true;
            }
        }
        return false;
    }

    public EnumeratedKey getUpdatedKeyInfo() throws SKSException {
        EnumeratedKey ek = new EnumeratedKey();
        while ((ek = prov_sess.sks.enumerateKeys(ek.getKeyHandle())) != null) {
            if (ek.getKeyHandle() == keyHandle) {
                return ek;
            }
        }
        throw new SKSException("Bad state");
    }

    public KeyProtectionInfo getKeyProtectionInfo() throws SKSException {
        return prov_sess.sks.getKeyProtectionInfo(keyHandle);
    }

    public void changePIN(String old_pin, String new_pin) throws SKSException, IOException {
        prov_sess.sks.changePin(keyHandle, getConditionalAuthorization(old_pin), getConditionalAuthorization(new_pin));
    }

    public byte[] signData(AsymSignatureAlgorithms alg_id, String pin, byte[] data) throws IOException {
        return prov_sess.sks.signHashedData(keyHandle,
                alg_id.getAlgorithmId(AlgorithmPreferences.SKS),
                null,
                getConditionalAuthorization(pin),
                alg_id.getDigestAlgorithm() == null ? data : alg_id.getDigestAlgorithm().digest(data));
    }

    public byte[] asymmetricKeyDecrypt(AsymEncryptionAlgorithms alg_id, String pin, byte[] data) throws IOException {
        return prov_sess.sks.asymmetricKeyDecrypt(keyHandle,
                alg_id.getAlgorithmId(AlgorithmPreferences.SKS),
                null,
                getConditionalAuthorization(pin),
                data);
    }

    public byte[] symmetricKeyEncrypt(SymEncryptionAlgorithms alg_id, boolean mode, byte[] parameters, String pin, byte[] data) throws IOException {
        return prov_sess.sks.symmetricKeyEncrypt(keyHandle,
                alg_id.getAlgorithmId(AlgorithmPreferences.SKS),
                mode,
                parameters,
                getConditionalAuthorization(pin),
                data);
    }

    public byte[] performHMAC(MACAlgorithms alg_id, String pin, byte[] data) throws IOException {
        return prov_sess.sks.performHmac(keyHandle,
                alg_id.getAlgorithmId(AlgorithmPreferences.SKS),
                null,
                getConditionalAuthorization(pin),
                data);
    }

    public void postUpdateKey(GenKey targetKey) throws SKSException, IOException, GeneralSecurityException {
        MacGenerator upd_mac = getEECertMacBuilder();
        byte[] authorization = targetKey.getPostProvMac(upd_mac, prov_sess);
        prov_sess.sks.postUpdateKey(keyHandle,
                targetKey.keyHandle,
                authorization,
                prov_sess.mac4call(upd_mac.getResult(), SecureKeyStore.METHOD_POST_UPDATE_KEY));
    }

    public void postCloneKey(GenKey targetKey) throws SKSException, IOException, GeneralSecurityException {
        MacGenerator upd_mac = getEECertMacBuilder();
        byte[] authorization = targetKey.getPostProvMac(upd_mac, prov_sess);
        prov_sess.sks.postCloneKeyProtection(keyHandle,
                targetKey.keyHandle,
                authorization,
                prov_sess.mac4call(upd_mac.getResult(), SecureKeyStore.METHOD_POST_CLONE_KEY_PROTECTION));
    }

    public void unlockKey(String puk) throws SKSException {
        prov_sess.sks.unlockKey(keyHandle, getConditionalAuthorization(puk));
    }

    public void setPIN(String puk, String pin) throws SKSException {
        prov_sess.sks.setPin(keyHandle, getConditionalAuthorization(puk), getConditionalAuthorization(pin));
    }

    public void deleteKey(String authorization) throws SKSException {
        prov_sess.sks.deleteKey(keyHandle, getConditionalAuthorization(authorization));
    }

    private byte[] getConditionalAuthorization(String authorization) throws SKSException {
        if (authorization == null) return null;
        try {
            return authorization.getBytes("UTF-8");
        } catch (IOException e) {
            throw new SKSException(e);
        }
    }
}

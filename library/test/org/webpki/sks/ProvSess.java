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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.GregorianCalendar;
import java.util.EnumSet;
import java.util.LinkedHashMap;
import java.util.Set;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.CertificateUtil;
import org.webpki.crypto.DemoKeyStore;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyData;
import org.webpki.sks.Grouping;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.ProvisioningSession;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

public class ProvSess {
    static class SoftHSM {
        ////////////////////////////////////////////////////////////////////////////////////////
        // Private and secret keys would in a HSM implementation be represented as handles
        ////////////////////////////////////////////////////////////////////////////////////////
        private static LinkedHashMap<PublicKey, PrivateKey> key_management_keys = new LinkedHashMap<PublicKey, PrivateKey>();

        static private void addKMK(KeyStore km_keystore) throws IOException, GeneralSecurityException {
            key_management_keys.put(km_keystore.getCertificate("mykey").getPublicKey(),
                    (PrivateKey) km_keystore.getKey("mykey", DemoKeyStore.getSignerPassword().toCharArray()));
        }

        static {
            try {
                addKMK(DemoKeyStore.getMybankDotComKeyStore());
                addKMK(DemoKeyStore.getSubCAKeyStore());
                addKMK(DemoKeyStore.getECDSAStore());
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(512);
                KeyPair key_pair = kpg.generateKeyPair();
                key_management_keys.put(key_pair.getPublic(), key_pair.getPrivate());  // INVALID
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        ECPrivateKey server_ec_private_key;

        byte[] session_key;

        public ECPublicKey generateEphemeralKey(KeyAlgorithms ec_key_algorithm) throws IOException {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec eccgen = new ECGenParameterSpec(ec_key_algorithm.getJceName());
                generator.initialize(eccgen, new SecureRandom());
                KeyPair kp = generator.generateKeyPair();
                server_ec_private_key = (ECPrivateKey) kp.getPrivate();
                return (ECPublicKey) kp.getPublic();
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        public void generateAndVerifySessionKey(ECPublicKey client_ephemeral_key,
                                                byte[] kdf_data,
                                                byte[] attestation_arguments,
                                                X509Certificate device_certificate,
                                                byte[] session_attestation) throws IOException {
            try {
                // SP800-56A C(2, 0, ECC CDH)
                KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
                key_agreement.init(server_ec_private_key);
                key_agreement.doPhase(client_ephemeral_key, true);
                byte[] Z = key_agreement.generateSecret();

                // The custom KDF
                Mac mac = Mac.getInstance(MACAlgorithms.HMAC_SHA256.getJceName());
                mac.init(new SecretKeySpec(Z, "RAW"));
                session_key = mac.doFinal(kdf_data);

                if (device_certificate == null) {
                    // The session key signature
                    mac = Mac.getInstance(MACAlgorithms.HMAC_SHA256.getJceName());
                    mac.init(new SecretKeySpec(session_key, "RAW"));
                    byte[] session_key_attest = mac.doFinal(attestation_arguments);
                    if (!ArrayUtil.compare(session_key_attest, session_attestation)) {
                        throw new IOException("Verify attestation failed");
                    }
                } else {
                    PublicKey device_public_key = device_certificate.getPublicKey();
                    AsymSignatureAlgorithms signatureAlgorithm = device_public_key instanceof RSAPublicKey ?
                            AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256;

                    // Verify that the session key signature was signed by the device key
                    SignatureWrapper verifier = new SignatureWrapper(signatureAlgorithm, device_public_key);
                    verifier.update(attestation_arguments);
                    if (!verifier.verify(session_attestation)) {
                        throw new IOException("Verify provisioning signature failed");
                    }
                }
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        public byte[] mac(byte[] data, byte[] key_modifier) throws IOException {
            try {
                Mac mac = Mac.getInstance(MACAlgorithms.HMAC_SHA256.getJceName());
                mac.init(new SecretKeySpec(ArrayUtil.add(session_key, key_modifier), "RAW"));
                return mac.doFinal(data);
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        public byte[] encrypt(byte[] data) throws IOException {
            try {
                byte[] key = mac(SecureKeyStore.KDF_ENCRYPTION_KEY, new byte[0]);
                Cipher crypt = Cipher.getInstance("AES/CBC/PKCS5Padding");
                byte[] iv = new byte[16];
                new SecureRandom().nextBytes(iv);
                crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new IvParameterSpec(iv));
                return ArrayUtil.add(iv, crypt.doFinal(data));
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        public byte[] generateNonce() throws IOException {
            byte[] rnd = new byte[32];
            new SecureRandom().nextBytes(rnd);
            return rnd;
        }

        public byte[] generateKeyManagementAuthorization(PublicKey keyManagementKey, byte[] data) throws IOException {
            try {
                SignatureWrapper km_sign = new SignatureWrapper(keyManagementKey instanceof RSAPublicKey ?
                        AsymSignatureAlgorithms.RSA_SHA256 : AsymSignatureAlgorithms.ECDSA_SHA256,
                        key_management_keys.get(keyManagementKey));
                km_sign.update(data);
                return km_sign.sign();
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }

        public PublicKey[] enumerateKeyManagementKeys() throws IOException, GeneralSecurityException {
            return key_management_keys.keySet().toArray(new PublicKey[0]);
        }
    }


    SoftHSM server_sess_key = new SoftHSM();

    static String override_session_key_algorithm;

    static KeyAlgorithms override_server_ephemeral_key_algorithm;

    String session_key_algorithm = SecureKeyStore.ALGORITHM_SESSION_ATTEST_1;


    static final String ISSUER_URI = "http://issuer.example.com/provsess";

    GregorianCalendar clientTime;

    int provisioning_handle;

    int sessionLifeTime = 10000;

    String serverSessionId;

    String clientSessionId;

    ECPublicKey server_ephemeral_key;

    Integer kmk_id;

    short mac_sequence_counter;

    SecureKeyStore sks;

    Device device;

    boolean privacy_enabled;

    boolean override_export_protection;

    byte overriden_export_protection;

    String override_key_entry_algorithm;

    boolean user_defined_pins = true;

    boolean user_modifiable_pins = false;

    boolean devicePinProtected = false;

    boolean fail_mac;

    InputMethod inputMethod = InputMethod.ANY;

    byte[] custom_key_parameters = null;

    String custom_key_algorithm = null;

    static class MacGenerator {
        private ByteArrayOutputStream baos;

        MacGenerator() {
            baos = new ByteArrayOutputStream();
        }

        private byte[] short2bytes(int s) {
            return new byte[]{(byte) (s >>> 8), (byte) s};
        }

        private byte[] int2bytes(int i) {
            return new byte[]{(byte) (i >>> 24), (byte) (i >>> 16), (byte) (i >>> 8), (byte) i};
        }

        void addBlob(byte[] data) throws IOException {
            baos.write(int2bytes(data.length));
            baos.write(data);
        }

        void addArray(byte[] data) throws IOException {
            baos.write(short2bytes(data.length));
            baos.write(data);
        }

        void addString(String string) throws IOException {
            addArray(string.getBytes("UTF-8"));
        }

        void addInt(int i) throws IOException {
            baos.write(int2bytes(i));
        }

        void addShort(int s) throws IOException {
            baos.write(short2bytes(s));
        }

        void addByte(byte b) {
            baos.write(b);
        }

        void addBool(boolean flag) {
            baos.write(flag ? (byte) 0x01 : (byte) 0x00);
        }

        byte[] getResult() {
            return baos.toByteArray();
        }

    }


    private byte[] getMacSequenceCounterAndUpdate() {
        int q = mac_sequence_counter++;
        return new byte[]{(byte) (q >>> 8), (byte) (q & 0xFF)};
    }

    byte[] mac4call(byte[] data, byte[] method) throws IOException, GeneralSecurityException {
        if (fail_mac) {
            fail_mac = false;
            data = ArrayUtil.add(data, new byte[]{5});
        }
        return server_sess_key.mac(data, ArrayUtil.add(method, getMacSequenceCounterAndUpdate()));
    }

    byte[] mac(byte[] data, byte[] key_modifier) throws IOException, GeneralSecurityException {
        return server_sess_key.mac(data, key_modifier);
    }

    byte[] attest(byte[] data) throws IOException, GeneralSecurityException {
        return server_sess_key.mac(data, ArrayUtil.add(SecureKeyStore.KDF_DEVICE_ATTESTATION, getMacSequenceCounterAndUpdate()));
    }

    void bad(String message) throws IOException {
        throw new IOException(message);
    }

    ///////////////////////////////////////////////////////////////////////////////////
    // Create provisioning session
    ///////////////////////////////////////////////////////////////////////////////////
    ProvSess(Device device, short sessionKeyLimit, Integer kmk_id, boolean privacy_enabled, String serv_sess) throws GeneralSecurityException, IOException {
        this.device = device;
        this.kmk_id = kmk_id;
        this.privacy_enabled = privacy_enabled;
        PublicKey keyManagementKey = kmk_id == null ? null : server_sess_key.enumerateKeyManagementKeys()[kmk_id];
        sks = device.sks;
        serverSessionId = serv_sess == null ? "S-" + Long.toHexString(new GregorianCalendar().getTimeInMillis()) + Long.toHexString(new SecureRandom().nextLong()) : serv_sess;
        String sess_key_alg = override_session_key_algorithm == null ? session_key_algorithm : override_session_key_algorithm;
        clientTime = new GregorianCalendar();
        ProvisioningSession sess =
                device.sks.createProvisioningSession(sess_key_alg,
                        privacy_enabled,
                        serverSessionId,
                        server_ephemeral_key = server_sess_key.generateEphemeralKey
                                (
                                        override_server_ephemeral_key_algorithm == null ? KeyAlgorithms.NIST_P_256 : override_server_ephemeral_key_algorithm
                                ),
                        ISSUER_URI,
                        keyManagementKey,
                        (int) (clientTime.getTimeInMillis() / 1000),
                        sessionLifeTime,
                        sessionKeyLimit);
        clientSessionId = sess.getClientSessionId();
        provisioning_handle = sess.getProvisioningHandle();

        MacGenerator kdf = new MacGenerator();
        kdf.addString(clientSessionId);
        kdf.addString(serverSessionId);
        kdf.addString(ISSUER_URI);
        kdf.addArray(getDeviceID());

        MacGenerator attestation_arguments = new MacGenerator();
        attestation_arguments.addString(clientSessionId);
        attestation_arguments.addString(serverSessionId);
        attestation_arguments.addString(ISSUER_URI);
        attestation_arguments.addArray(getDeviceID());
        attestation_arguments.addString(sess_key_alg);
        attestation_arguments.addBool(privacy_enabled);
        attestation_arguments.addArray(server_ephemeral_key.getEncoded());
        attestation_arguments.addArray(sess.getClientEphemeralKey().getEncoded());
        attestation_arguments.addArray(keyManagementKey == null ? new byte[0] : keyManagementKey.getEncoded());
        attestation_arguments.addInt((int) (clientTime.getTimeInMillis() / 1000));
        attestation_arguments.addInt(sessionLifeTime);
        attestation_arguments.addShort(sessionKeyLimit);

        server_sess_key.generateAndVerifySessionKey(sess.getClientEphemeralKey(),
                kdf.getResult(),
                attestation_arguments.getResult(),
                privacy_enabled ? null : device.device_info.getCertificatePath()[0],
                sess.getAttestation());
    }

    public void byPassKMK(int kmk_id) {
        this.kmk_id = kmk_id;
    }

    public ProvSess(Device device, short sessionKeyLimit, Integer kmk_id) throws GeneralSecurityException, IOException {
        this(device, sessionKeyLimit, kmk_id, false, null);
    }

    public ProvSess(Device device, String serv_sess_id) throws GeneralSecurityException, IOException {
        this(device, (short) 50, null, false, serv_sess_id);
    }

    public ProvSess(Device device) throws GeneralSecurityException, IOException {
        this(device, (short) 50, null);
    }

    public ProvSess(Device device, short sessionKeyLimit) throws GeneralSecurityException, IOException {
        this(device, sessionKeyLimit, null);
    }

    public ProvSess(Device device, Integer kmk_id) throws GeneralSecurityException, IOException {
        this(device, (short) 50, kmk_id);
    }

    public void closeSession() throws IOException, GeneralSecurityException {
        byte[] nonce = server_sess_key.generateNonce();
        MacGenerator close = new MacGenerator();
        close.addString(clientSessionId);
        close.addString(serverSessionId);
        close.addString(ISSUER_URI);
        close.addArray(nonce);
        byte[] result = sks.closeProvisioningSession(provisioning_handle,
                nonce,
                mac4call(close.getResult(),
                        SecureKeyStore.METHOD_CLOSE_PROVISIONING_SESSION));
        MacGenerator check = new MacGenerator();
        check.addArray(nonce);
        if (!ArrayUtil.compare(attest(check.getResult()), result)) {
            bad("Final attestation failed!");
        }
    }

    public void abortSession() throws IOException {
        sks.abortProvisioningSession(provisioning_handle);
    }


    public void failMAC() {
        fail_mac = true;
    }


    public void overrideExportProtection(byte export_policy) {
        override_export_protection = true;
        overriden_export_protection = export_policy;
    }

    public void makePINsServerDefined() {
        user_defined_pins = false;
    }

    public void makePINsUserModifiable() {
        user_modifiable_pins = true;
    }

    public void setInputMethod(InputMethod inputMethod) {
        this.inputMethod = inputMethod;
    }

    public void setKeyAlgorithm(String key_algorithm) {
        custom_key_algorithm = key_algorithm;
    }

    public void setKeyParameters(byte[] keyParameters) {
        custom_key_parameters = keyParameters;
    }

    public byte[] getPassphraseBytes(PassphraseFormat format, String passphrase) throws IOException {
        if (format == PassphraseFormat.BINARY) {
            return DebugFormatter.getByteArrayFromHex(passphrase);
        }
        return passphrase.getBytes("UTF-8");
    }

    public PUKPol createPUKPolicy(String id, PassphraseFormat format, int retryLimit, String puk_value) throws IOException, GeneralSecurityException {
        PUKPol pukPolicy = new PUKPol();
        byte[] encryptedValue = server_sess_key.encrypt(getPassphraseBytes(format, puk_value));
        MacGenerator puk_policy_mac = new MacGenerator();
        puk_policy_mac.addString(id);
        puk_policy_mac.addArray(encryptedValue);
        puk_policy_mac.addByte(format.getSksValue());
        puk_policy_mac.addShort(retryLimit);
        pukPolicy.id = id;
        pukPolicy.puk_policy_handle = sks.createPukPolicy(provisioning_handle,
                id,
                encryptedValue,
                format.getSksValue(),
                (short) retryLimit,
                mac4call(puk_policy_mac.getResult(), SecureKeyStore.METHOD_CREATE_PUK_POLICY));
        return pukPolicy;
    }

    public PINPol createPINPolicy(String id, PassphraseFormat format, int minLength, int maxLength, int retryLimit, PUKPol pukPolicy) throws IOException, GeneralSecurityException {
        return createPINPolicy(id, format, EnumSet.noneOf(PatternRestriction.class), Grouping.NONE, minLength, maxLength, retryLimit, pukPolicy);
    }

    public PINPol createPINPolicy(String id,
                                  PassphraseFormat format,
                                  Set<PatternRestriction> patternRestrictions,
                                  Grouping grouping,
                                  int minLength,
                                  int maxLength,
                                  int retryLimit,
                                  PUKPol pukPolicy) throws IOException, GeneralSecurityException {
        PINPol pinPolicy = new PINPol();
        boolean userDefined = user_defined_pins;
        boolean userModifiable = user_modifiable_pins;
        int puk_policy_handle = pukPolicy == null ? 0 : pukPolicy.puk_policy_handle;
        MacGenerator pin_policy_mac = new MacGenerator();
        pin_policy_mac.addString(id);
        pin_policy_mac.addString(pukPolicy == null ? SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE : pukPolicy.id);
        pin_policy_mac.addBool(userDefined);
        pin_policy_mac.addBool(userModifiable);
        pin_policy_mac.addByte(format.getSksValue());
        pin_policy_mac.addShort(retryLimit);
        pin_policy_mac.addByte(grouping.getSksValue());
        pin_policy_mac.addByte(PatternRestriction.getSksValue(patternRestrictions));
        pin_policy_mac.addShort(minLength);
        pin_policy_mac.addShort(maxLength);
        pin_policy_mac.addByte(inputMethod.getSksValue());
        pinPolicy.id = id;
        pinPolicy.userDefined = userDefined;
        pinPolicy.format = format;
        pinPolicy.pin_policy_handle = sks.createPinPolicy(provisioning_handle,
                id,
                puk_policy_handle,
                userDefined,
                userModifiable,
                format.getSksValue(),
                (short) retryLimit,
                grouping.getSksValue(),
                PatternRestriction.getSksValue(patternRestrictions),
                (byte) minLength,
                (byte) maxLength,
                inputMethod.getSksValue(),
                mac4call(pin_policy_mac.getResult(), SecureKeyStore.METHOD_CREATE_PIN_POLICY));
        return pinPolicy;
    }

    public GenKey createKey(String id,
                            KeyAlgorithms key_algorithm,
                            String pin_value,
                            PINPol pinPolicy,
                            AppUsage keyUsage) throws SKSException, IOException, GeneralSecurityException {
        return createKey(id, key_algorithm, pin_value, pinPolicy, keyUsage, null);
    }

    public GenKey createKey(String id,
                            KeyAlgorithms key_algorithm,
                            String pin_value,
                            PINPol pinPolicy,
                            AppUsage appUsage,
                            String[] endorsed_algorithm) throws SKSException, IOException, GeneralSecurityException {
        byte[] serverSeed = new byte[32];
        new SecureRandom().nextBytes(serverSeed);
        return createKey(id,
                SecureKeyStore.ALGORITHM_KEY_ATTEST_1,
                serverSeed,
                pinPolicy,
                pin_value,
                BiometricProtection.NONE /* biometricProtection */,
                ExportProtection.NON_EXPORTABLE /* export_policy */,
                DeleteProtection.NONE /* delete_policy */,
                false /* enablePinCaching */,
                appUsage,
                "" /* friendlyName */,
                new KeySpecifier(key_algorithm),
                endorsed_algorithm);
    }


    public GenKey createKey(String id,
                            String key_entry_algorithm,
                            byte[] serverSeed,
                            PINPol pinPolicy,
                            String pin_value,
                            BiometricProtection biometricProtection,
                            ExportProtection exportProtection,
                            DeleteProtection deleteProtection,
                            boolean enablePinCaching,
                            AppUsage appUsage,
                            String friendlyName,
                            KeySpecifier keySpecifier,
                            String[] endorsedAlgorithms) throws SKSException, IOException, GeneralSecurityException {
        key_entry_algorithm = override_key_entry_algorithm == null ? key_entry_algorithm : override_key_entry_algorithm;
        String key_algorithm = custom_key_algorithm == null ? keySpecifier.getKeyAlgorithm().getAlgorithmId(AlgorithmPreferences.SKS) : custom_key_algorithm;
        byte[] keyParameters = custom_key_parameters == null ? keySpecifier.getParameters() : custom_key_parameters;
        String[] sorted_algorithms = endorsedAlgorithms == null ? new String[0] : endorsedAlgorithms;
        byte actual_export_policy = override_export_protection ? overriden_export_protection : exportProtection.getSksValue();
        MacGenerator key_entry_mac = new MacGenerator();
        key_entry_mac.addString(id);
        key_entry_mac.addString(key_entry_algorithm);
        key_entry_mac.addArray(serverSeed == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : serverSeed);
        byte[] encrypted_pin_value = null;
        if (pinPolicy == null) {
            if (pin_value != null) {
                encrypted_pin_value = pin_value.getBytes("UTF-8");
            }
        } else {
            encrypted_pin_value = getPassphraseBytes(pinPolicy.format, pin_value);
            if (!pinPolicy.userDefined) {
                encrypted_pin_value = server_sess_key.encrypt(encrypted_pin_value);
            }
        }
        key_entry_mac.addString(pinPolicy == null ?
                SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE
                :
                pinPolicy.id);
        if (pinPolicy == null || pinPolicy.userDefined) {
            key_entry_mac.addString(SecureKeyStore.CRYPTO_STRING_NOT_AVAILABLE);
        } else {
            key_entry_mac.addArray(encrypted_pin_value);
        }
        key_entry_mac.addBool(devicePinProtected);
        key_entry_mac.addBool(enablePinCaching);
        key_entry_mac.addByte(biometricProtection.getSksValue());
        key_entry_mac.addByte(actual_export_policy);
        key_entry_mac.addByte(deleteProtection.getSksValue());
        key_entry_mac.addByte(appUsage.getSksValue());
        key_entry_mac.addString(friendlyName == null ? "" : friendlyName);
        key_entry_mac.addString(key_algorithm);
        key_entry_mac.addArray(keyParameters == null ? SecureKeyStore.ZERO_LENGTH_ARRAY : keyParameters);
        for (String algorithm : sorted_algorithms) {
            key_entry_mac.addString(algorithm);
        }
        KeyData key_entry = sks.createKeyEntry(provisioning_handle,
                id,
                key_entry_algorithm,
                serverSeed,
                devicePinProtected,
                pinPolicy == null ? 0 : pinPolicy.pin_policy_handle,
                encrypted_pin_value,
                enablePinCaching,
                biometricProtection.getSksValue(),
                actual_export_policy,
                deleteProtection.getSksValue(),
                appUsage.getSksValue(),
                friendlyName,
                key_algorithm,
                keyParameters,
                sorted_algorithms,
                mac4call(key_entry_mac.getResult(), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));
        MacGenerator key_attestation = new MacGenerator();
        key_attestation.addString(id);
        key_attestation.addArray(key_entry.getPublicKey().getEncoded());
        if (!ArrayUtil.compare(attest(key_attestation.getResult()), key_entry.getAttestation())) {
            bad("Failed key attest");
        }
        GenKey key = new GenKey();
        key.id = id;
        key.keyHandle = key_entry.getKeyHandle();
        String return_alg = KeyAlgorithms.getKeyAlgorithm(key.publicKey = key_entry.getPublicKey(), keyParameters != null).getAlgorithmId(AlgorithmPreferences.SKS);
        BigInteger exponent = RSAKeyGenParameterSpec.F4;
        if (keyParameters != null) {
            exponent = new BigInteger(keyParameters);
        }
        if (!return_alg.equals(key_algorithm)) {
            bad("Bad return algorithm: " + return_alg);
        }
        if (key.publicKey instanceof RSAPublicKey && !((RSAPublicKey) key.publicKey).getPublicExponent().equals(exponent)) {
            bad("Wrong exponent RSA returned");
        }
        key.prov_sess = this;
        return key;
    }

    void setCertificate(int keyHandle, String id, PublicKey publicKey, X509Certificate[] certificatePath) throws IOException, GeneralSecurityException {
        MacGenerator set_certificate = new MacGenerator();
        set_certificate.addArray(publicKey.getEncoded());
        set_certificate.addString(id);
        certificatePath = CertificateUtil.getSortedPath(certificatePath);
        for (X509Certificate certificate : certificatePath) {
            set_certificate.addArray(certificate.getEncoded());
        }
        sks.setCertificatePath(keyHandle,
                certificatePath,
                mac4call(set_certificate.getResult(), SecureKeyStore.METHOD_SET_CERTIFICATE_PATH));
    }

    public void postDeleteKey(GenKey key) throws IOException, GeneralSecurityException {
        MacGenerator upd_mac = new MacGenerator();
        byte[] authorization = key.getPostProvMac(upd_mac, this);
        sks.postDeleteKey(provisioning_handle, key.keyHandle, authorization, mac4call(upd_mac.getResult(), SecureKeyStore.METHOD_POST_DELETE_KEY));
    }

    public void postUnlockKey(GenKey key) throws IOException, GeneralSecurityException {
        MacGenerator upd_mac = new MacGenerator();
        byte[] authorization = key.getPostProvMac(upd_mac, this);
        sks.postUnlockKey(provisioning_handle, key.keyHandle, authorization, mac4call(upd_mac.getResult(), SecureKeyStore.METHOD_POST_UNLOCK_KEY));
    }

    public boolean exists() throws SKSException {
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession();
        while ((eps = sks.enumerateProvisioningSessions(eps.getProvisioningHandle(), false)) != null) {
            if (eps.getProvisioningHandle() == provisioning_handle) {
                return true;
            }
        }
        return false;
    }

    public byte[] getDeviceID() throws GeneralSecurityException {
        return privacy_enabled ? SecureKeyStore.KDF_ANONYMOUS : device.device_info.getCertificatePath()[0].getEncoded();
    }

    public byte[] serverSessionSign(byte[] data) throws IOException, GeneralSecurityException {
        return mac(data, SecureKeyStore.KDF_EXTERNAL_SIGNATURE);
    }
}

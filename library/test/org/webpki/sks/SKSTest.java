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
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.interfaces.ECPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;

import java.util.EnumSet;
import java.util.Set;
import java.util.Vector;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.BeforeClass;
import org.junit.rules.TestName;

import static org.junit.Assert.*;

import org.webpki.crypto.AlgorithmPreferences;
import org.webpki.crypto.AsymEncryptionAlgorithms;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.MACAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.SymEncryptionAlgorithms;
import org.webpki.crypto.CustomCryptoProvider;

import org.webpki.sks.AppUsage;
import org.webpki.sks.BiometricProtection;
import org.webpki.sks.DeleteProtection;
import org.webpki.sks.DeviceInfo;
import org.webpki.sks.EnumeratedProvisioningSession;
import org.webpki.sks.ExportProtection;
import org.webpki.sks.Extension;
import org.webpki.sks.Grouping;
import org.webpki.sks.InputMethod;
import org.webpki.sks.KeyProtectionInfo;
import org.webpki.sks.PassphraseFormat;
import org.webpki.sks.PatternRestriction;
import org.webpki.sks.Property;
import org.webpki.sks.SKSException;
import org.webpki.sks.SecureKeyStore;
import org.webpki.sks.ws.TrustedGUIAuthorization;
import org.webpki.sks.ws.WSSpecific;

import org.webpki.util.ArrayUtil;

import org.webpki.keygen2.KeyGen2Constants;

public class SKSTest {
    static final byte[] TEST_STRING = new byte[]{'S', 'u', 'c', 'c', 'e', 's', 's', ' ', 'o', 'r', ' ', 'n', 'o', 't', '?'};

    static SecureKeyStore sks;

    static TrustedGUIAuthorization tga;

    static boolean reference_implementation;

    static boolean standalone_testing;

    static Vector<Integer> prov_sessions = new Vector<Integer>();

    static Device device;

    static boolean bc_loaded;

    @BeforeClass
    public static void openFile() throws Exception {
        standalone_testing = new Boolean(System.getProperty("sks.standalone"));
        bc_loaded = CustomCryptoProvider.conditionalLoad(true);
        sks = (SecureKeyStore) Class.forName(System.getProperty("sks.implementation")).newInstance();
        if (sks instanceof WSSpecific) {
            tga = (TrustedGUIAuthorization) Class.forName(System.getProperty("sks.auth.gui")).newInstance();
            ((WSSpecific) sks).setTrustedGUIAuthorizationProvider(tga);
            String deviceId = System.getProperty("sks.device");
            if (deviceId != null && deviceId.length() != 0) {
                ((WSSpecific) sks).setDeviceID(deviceId);
            }
        }
        device = new Device(sks);
        DeviceInfo dev = device.device_info;
        reference_implementation = dev.getVendorName().contains(SKSReferenceImplementation.SKS_VENDOR_NAME)
                ||
                new Boolean(System.getProperty("sks.referenceimplementation"));
        if (reference_implementation) {
            System.out.println("Reference Implementation");
        }
        System.out.println("Description: " + dev.getVendorDescription());
        System.out.println("Vendor: " + dev.getVendorName());
        System.out.println("API Level: " + dev.getApiLevel());
        System.out.println("Trusted GUI: " + (tga == null ? "N/A" : tga.getImplementation()));
        System.out.println("Testing mode: " + (standalone_testing ? "StandAlone" : "MultiThreaded"));
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession();
        while ((eps = sks.enumerateProvisioningSessions(eps.getProvisioningHandle(), true)) != null) {
            prov_sessions.add(eps.getProvisioningHandle());
        }
        if (!prov_sessions.isEmpty()) {
            System.out.println("There were " + prov_sessions.size() + " open sessions before test started");
        }
    }

    @AfterClass
    public static void closeFile() throws Exception {
        EnumeratedProvisioningSession eps = new EnumeratedProvisioningSession();
        int i = 0;
        while ((eps = sks.enumerateProvisioningSessions(eps.getProvisioningHandle(), true)) != null) {
            i++;
            if (!prov_sessions.contains(eps.getProvisioningHandle())) {
                fail("Remaining session:" + eps.getProvisioningHandle());
            }
        }
        assertTrue("Sess mismatch", i == prov_sessions.size());
    }

    @Before
    public void setup() throws Exception {
        if (sks instanceof WSSpecific) {
            ((WSSpecific) sks).logEvent("Testing:" + _name.getMethodName());
        }
    }

    @After
    public void teardown() throws Exception {
    }

    @Rule
    public TestName _name = new TestName();

    void edgeDeleteCase(boolean post) throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key3 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        if (post) {
            key3.postUpdateKey(key1);
        } else {
            sks.deleteKey(key1.keyHandle, null);
        }
        try {
            if (post) {
                sks.deleteKey(key1.keyHandle, null);
            } else {
                key3.postUpdateKey(key1);
            }
            sess2.closeSession();
            fail("Multiple updates using the same key");
        } catch (SKSException e) {
        }
    }

    void checkException(SKSException e, String compare_message) {
        checkException(e, compare_message, null);
    }

    void checkException(SKSException e, String compare_message, Integer sks_error_code) {
        String m = e.getMessage();
        if (reference_implementation && m != null && compare_message.indexOf('#') == m.indexOf('#')) {
            int i = m.indexOf('#') + 1;
            int q = 0;
            while ((q + i) < m.length() && m.charAt(i + q) >= '0' && m.charAt(i + q) <= '9') {
                q++;
            }
            if (q != 0) {
                m = m.substring(0, i) + m.substring(i + q);
            }
        }
        if (m == null || (reference_implementation && !m.equals(compare_message))) {
            fail("Check: " + m + "\n" + compare_message);
        }
        if (sks_error_code != null) {
            assertTrue("Error code: " + sks_error_code.intValue() + " found " + e.getError(),
                    sks_error_code.intValue() == e.getError());
        }
    }

    void algOrder(String[] algorithms, String culprit_alg) throws Exception {
        try {
            ProvSess sess = new ProvSess(device, 0);
            sess.createKey("Key.1",
                    KeyAlgorithms.RSA2048,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION,
                    algorithms);
            assertTrue("Should have thrown", culprit_alg == null);
            sess.abortSession();
        } catch (SKSException e) {
            assertFalse("Should not have thrown", culprit_alg == null);
            checkException(e, "Duplicate or incorrectly sorted algorithm: " + culprit_alg);
        }
    }

    void authorizationErrorCheck(SKSException e) {
        checkException(e, "\"" + SecureKeyStore.VAR_AUTHORIZATION + "\" error for key #", SKSException.ERROR_AUTHORIZATION);
    }

    void sessionNotOpenCheck(SKSException e) {
        assertTrue("Not open", e.getError() == SKSException.ERROR_NO_SESSION);
        if (reference_implementation) {
            assertTrue("session", e.getMessage().startsWith("Session not open: "));
        }
    }

    void updateReplace(boolean order) throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device, 0);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key2 = sess2.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key3 = sess2.createKey("Key.1",
                KeyAlgorithms.RSA2048,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        if (order) key3.postCloneKey(key1);
        key2.postUpdateKey(key1);
        if (!order) key3.postCloneKey(key1);
        sess2.closeSession();
        assertTrue("Old key should exist after update", key1.exists());
        assertFalse("New key should NOT exist after update", key2.exists());
        assertTrue("New key should exist after clone", key3.exists());
        assertTrue("Ownership error", key1.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertTrue("Ownership error", key3.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertFalse("Managed sessions MUST be deleted", sess.exists());
        try {
            key3.signData(AsymSignatureAlgorithms.RSA_SHA256, "", TEST_STRING);
            fail("Bad PIN should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        try {
            byte[] result = key3.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
            SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA256, key3.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature key3", verify.verify(result));
            result = key1.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            verify = new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, key2.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature key1", verify.verify(result));
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
    }

    Extension extensionTest(byte subType, String qualifier, byte[] extension_data, String error) throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        String type = "http://example.com/define";
        try {
            if (qualifier == null) qualifier = "";
            key.addExtension(type, subType, qualifier, extension_data);
            assertTrue("Should pass", error == null);
            sess.closeSession();
            Extension ext = device.sks.getExtension(key.keyHandle, type);
            assertTrue("Ext data", ArrayUtil.compare(ext.getExtensionData(), extension_data));
            assertTrue("Qualifier", qualifier.equals(ext.getQualifier()));
            assertTrue("Sub type", ext.getSubType() == subType);
            if (subType == SecureKeyStore.SUB_TYPE_PROPERTY_BAG) {
                int i = 0;
                int writables = 0;
                while (i < extension_data.length) {
                    i += (((extension_data[i++] << 8) & 0xFF00) | (extension_data[i++] & 0xFF)) + 2;
                    if (extension_data[i++] == 1) {
                        writables++;
                    }
                    i += (((extension_data[i++] << 8) & 0xFF00) | (extension_data[i++] & 0xFF)) + 2;
                }
                int writes = 0;
                for (Property prop : ext.getProperties()) {
                    try {
                        String newval = "yes";
                        device.sks.setProperty(key.keyHandle, type, prop.getName(), newval);
                        writes++;
                        assertTrue("Writable", prop.isWritable());
                        boolean found = false;
                        for (Property newprop : device.sks.getExtension(key.keyHandle, type).getProperties()) {
                            if (prop.getName().equals(newprop.getName())) {
                                found = true;
                                assertTrue("Updated", newprop.getValue().equals(newval));
                                break;
                            }
                        }
                        assertTrue("Prop name?", found);
                    } catch (SKSException e) {
                        assertFalse("Read only", prop.isWritable());
                        checkException(e, "\"" + SecureKeyStore.VAR_PROPERTY + "\" not writable: " + prop.getName(), SKSException.ERROR_NOT_ALLOWED);
                    }
                }
                assertTrue("Writables", writes == writables);
            }
            return ext;
        } catch (SKSException e) {
            assertFalse("Shouldn't fail=" + e.getMessage(), error == null);
            checkException(e, error);
        }
        return null;
    }

    void retryCountTest(int retryLimit, boolean puk_ok, boolean pin_ok) throws Exception {
        ProvSess sess = new ProvSess(device);
        try {
            sess.createPUKPolicy("PUK",
                    PassphraseFormat.NUMERIC,
                    (short) retryLimit /* retryLimit*/,
                    "012355" /* puk */);
            assertTrue("Not OK for PUK", puk_ok);
            sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) retryLimit /* retryLimit*/,
                    null /* pukPolicy */);
            assertTrue("Not OK for PIN", pin_ok);
            sess.abortSession();
        } catch (SKSException e) {
            assertFalse("Should have passed...", puk_ok && pin_ok);
            checkException(e, "Invalid \"" + SecureKeyStore.VAR_RETRY_LIMIT + "\" value=" + retryLimit);
        }
    }

    void checkIDObject(String id, boolean ok) throws Exception {
        try {
            ProvSess sess = new ProvSess(device, id);
            assertTrue("Should have failed", ok);
            sess.closeSession();
        } catch (SKSException e) {
            checkException(e, "Malformed \"" + SecureKeyStore.VAR_SERVER_SESSION_ID + "\" : " + id);
        }
        try {
            ProvSess sess = new ProvSess(device);
            sess.createPINPolicy(id,
                    PassphraseFormat.NUMERIC,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            assertTrue("Should have failed", ok);
            sess.abortSession();
        } catch (SKSException e) {
            checkException(e, "Malformed \"" + SecureKeyStore.VAR_ID + "\" : " + id);
        }
    }

    class userModifyPINCheck {
        GenKey key;
        String good_pin;
        String good_puk = "123456";

        userModifyPINCheck(String good_pin, PassphraseFormat format, PatternRestriction[] restrictions) throws Exception {
            this.good_pin = good_pin;
            Set<PatternRestriction> patternRestrictions = EnumSet.noneOf(PatternRestriction.class);
            for (PatternRestriction pattern : restrictions) {
                patternRestrictions.add(pattern);
            }
            ProvSess sess = new ProvSess(device);
            sess.makePINsUserModifiable();
            PUKPol puk_pol = sess.createPUKPolicy("PUK",
                    PassphraseFormat.NUMERIC,
                    (short) 3 /* retryLimit */,
                    good_puk /* puk */);
            PINPol pin_pol = sess.createPINPolicy("PIN",
                    format,
                    patternRestrictions,
                    Grouping.NONE,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit */,
                    puk_pol /* pukPolicy */);
            key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pin_pol /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
        }

        void test(String pin, boolean pass) throws Exception {
            for (int i = 0; i < 5; i++)  // Just to make sure that error-count isn't affected
            {
                try {
                    key.setPIN(good_puk, pin);
                    assertTrue("Shouldn't pass", pass);
                    key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, pin, TEST_STRING);
                    key.changePIN(pin, good_pin);
                } catch (SKSException e) {
                    assertFalse("Should pass", pass);
                }
            }
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
        }
    }

    boolean PINCheck(PassphraseFormat format,
                     PatternRestriction[] patterns,
                     String pin) throws IOException, GeneralSecurityException {
        try {
            Set<PatternRestriction> patternRestrictions = EnumSet.noneOf(PatternRestriction.class);
            if (patterns != null) {
                for (PatternRestriction pattern : patterns) {
                    patternRestrictions.add(pattern);
                }
            }
            ProvSess sess = new ProvSess(device);
            PINPol pin_pol = sess.createPINPolicy("PIN",
                    format,
                    patternRestrictions,
                    Grouping.NONE,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    pin /* pin_value */,
                    pin_pol /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.abortSession();
        } catch (SKSException e) {
            return false;
        }
        return true;
    }

    boolean PUKCheck(PassphraseFormat format, String puk) throws IOException, GeneralSecurityException {
        try {
            ProvSess sess = new ProvSess(device);
            sess.createPUKPolicy("PUK",
                    format,
                    (short) 3 /* retryLimit*/,
                    puk /* puk */);
            sess.abortSession();
        } catch (SKSException e) {
            return false;
        }
        return true;
    }

    void PINstress(ProvSess sess) throws Exception {
        String good_pin = "1563";
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();

        for (int count = 0; count < 2; count++) {
            try {
                key.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin + "2", TEST_STRING);
                fail("Bad PIN should not work");
            } catch (SKSException e) {
                authorizationErrorCheck(e);
            }
        }
        try {
            key.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
        for (int count = 0; count < 3; count++) {
            try {
                key.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin + "2", TEST_STRING);
                fail("Bad PIN should not work");
            } catch (SKSException e) {
                authorizationErrorCheck(e);
            }
        }
        try {
            key.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
            fail("Good PIN but too many errors should NOT work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
    }

    void sessionLimitTest(int limit, boolean encrypted_pin, boolean fail_hard) throws Exception {
        ProvSess sess = new ProvSess(device, (short) limit);
        if (encrypted_pin) {
            sess.makePINsServerDefined();
        }
        try {
            String good_pin = "1563";
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);

            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            assertFalse("Should have failed", fail_hard);
        } catch (SKSException e) {
            if (!fail_hard) fail(e.getMessage());
            return;
        }
    }

    boolean PINGroupCheck(boolean same_pin, Grouping grouping) throws IOException, GeneralSecurityException {
        try {
            String pin1 = "1234";
            String pin2 = "4567";
            ProvSess sess = new ProvSess(device);
            PINPol pin_pol = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    grouping,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    pin1 /* pin_value */,
                    pin_pol /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            if (grouping == Grouping.SIGNATURE_PLUS_STANDARD) {
                sess.createKey("Key.1s",
                        KeyAlgorithms.NIST_P_256,
                        pin1 /* pin_value */,
                        pin_pol /* pinPolicy */,
                        AppUsage.UNIVERSAL).setCertificate(cn());
                sess.createKey("Key.2s",
                        KeyAlgorithms.NIST_P_256,
                        same_pin ? pin1 : pin2 /* pin_value */,
                        pin_pol /* pinPolicy */,
                        AppUsage.SIGNATURE).setCertificate(cn());
            }
            sess.createKey("Key.2",
                    KeyAlgorithms.NIST_P_256,
                    same_pin ? pin1 : pin2 /* pin_value */,
                    pin_pol /* pinPolicy */,
                    AppUsage.SIGNATURE).setCertificate(cn());
            sess.abortSession();
        } catch (SKSException e) {
            return false;
        }
        return true;
    }

    void lockECKey(GenKey key, String good_pin) throws Exception {
        for (int i = 1; i < 4; i++) {
            try {
                key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin + "4", TEST_STRING);
                assertTrue("PIN fail", i < 3);
            } catch (SKSException e) {
                authorizationErrorCheck(e);
            }
        }
        try {
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            fail("PIN fail");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
    }

    void badKeySpec(String key_algorithm, byte[] keyParameters, String expected_message) throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.setKeyAlgorithm(key_algorithm);
        sess.setKeyParameters(keyParameters);
        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            fail("Bad ones shouldn't pass");
        } catch (SKSException e) {
            checkException(e, expected_message);
        }
    }

    void updateTest(AppUsage appUsage) throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key2 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                appUsage).setCertificate(cn());
        try {
            key2.postUpdateKey(key1);
            sess2.closeSession();
            assertTrue("Must be identical", appUsage == AppUsage.AUTHENTICATION);
            assertTrue("Key should exist even after update", key1.exists());
            assertFalse("Key has been used and should be removed", key2.exists());
            assertTrue("Ownership error", key1.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
            assertFalse("Managed sessions MUST be deleted", sess.exists());
        } catch (SKSException e) {
            assertFalse("Must not be identical", appUsage == AppUsage.AUTHENTICATION);
            checkException(e, "Updated keys must have the same \"" + SecureKeyStore.VAR_APP_USAGE + "\" as the target key");
        }
    }

    void testCloning(Grouping grouping, AppUsage appUsage) throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device, 0);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                grouping,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key2 = sess2.createKey("Key.1",
                KeyAlgorithms.RSA2048,
                null /* pin_value */,
                null /* pinPolicy */,
                appUsage).setCertificate(cn());
        try {
            key2.postCloneKey(key1);
            sess2.closeSession();
            assertTrue("Grouping must be shared", grouping == Grouping.SHARED);
            assertTrue("Old key should exist after clone", key1.exists());
            assertTrue("New key should exist after clone", key2.exists());
            assertTrue("Ownership error", key1.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
            assertFalse("Managed sessions MUST be deleted", sess.exists());
            try {
                key2.signData(AsymSignatureAlgorithms.RSA_SHA256, "1111", TEST_STRING);
                fail("Bad PIN should not work");
            } catch (SKSException e) {
                authorizationErrorCheck(e);
            }
            try {
                byte[] result = key2.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
                SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA256, key2.getPublicKey());
                verify.update(TEST_STRING);
                assertTrue("Bad signature key2", verify.verify(result));
                result = key1.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
                verify = new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, key1.getPublicKey());
                verify.update(TEST_STRING);
                assertTrue("Bad signature key1", verify.verify(result));
            } catch (SKSException e) {
                fail("Good PIN should work");
            }
        } catch (SKSException e) {
            assertFalse("Grouping must not be shared", grouping == Grouping.SHARED);
            checkException(e, "A cloned key protection must have PIN grouping=\"shared\"");
        }
    }

    void serverSeed(int length) throws Exception {
        byte[] serverSeed = new byte[length];
        new SecureRandom().nextBytes(serverSeed);
        ProvSess sess = new ProvSess(device);
        sess.createKey("Key.1",
                SecureKeyStore.ALGORITHM_KEY_ATTEST_1,
                serverSeed,
                null,
                null,
                BiometricProtection.NONE /* biometricProtection */,
                ExportProtection.NON_EXPORTABLE /* export_policy */,
                DeleteProtection.NONE /* delete_policy */,
                false /* enablePinCaching */,
                AppUsage.AUTHENTICATION,
                "" /* friendlyName */,
                new KeySpecifier(KeyAlgorithms.RSA1024),
                null).setCertificate(cn());
        sess.closeSession();
    }

    void rsaEncryptionTest(AsymEncryptionAlgorithms encryption_algorithm) throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.ENCRYPTION).setCertificate(cn());
        sess.closeSession();
        Cipher cipher = Cipher.getInstance(encryption_algorithm.getJceName());
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
        byte[] enc = cipher.doFinal(TEST_STRING);
        assertTrue("Encryption error" + encryption_algorithm,
                ArrayUtil.compare(device.sks.asymmetricKeyDecrypt(key.keyHandle,
                        encryption_algorithm.getAlgorithmId(AlgorithmPreferences.SKS),
                        null,
                        good_pin.getBytes("UTF-8"),
                        enc), TEST_STRING) ||
                        (!bc_loaded && encryption_algorithm != AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5));
        try {
            device.sks.asymmetricKeyDecrypt(key.keyHandle,
                    AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS),
                    null,
                    good_pin.getBytes("UTF-8"),
                    enc);
            fail("Alg error");
        } catch (SKSException e) {
            checkException(e, "Algorithm does not match operation: http://www.w3.org/2001/04/xmldsig-more#rsa-sha256");
        }
        try {
            device.sks.asymmetricKeyDecrypt(key.keyHandle,
                    encryption_algorithm.getAlgorithmId(AlgorithmPreferences.SKS),
                    new byte[]{6},
                    good_pin.getBytes("UTF-8"),
                    enc);
            fail("Parm error");
        } catch (SKSException e) {
            checkException(e, "\"" + SecureKeyStore.VAR_PARAMETERS + "\" for key # do not match algorithm");
        }
        try {
            key.asymmetricKeyDecrypt(encryption_algorithm, good_pin + "4", enc);
            fail("PIN error");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
    }

    void create3Keys(String s_pin, String a_pin, String e_pin) throws Exception {
        boolean sa = s_pin.equals(a_pin);
        boolean ae = a_pin.equals(e_pin);
        boolean se = s_pin.equals(e_pin);
        String other_pin = "5555";
        for (Grouping pg : Grouping.values()) {
            String good_puk = "17644";
            short pin_retry = 3;
            ProvSess sess = new ProvSess(device);
            sess.makePINsUserModifiable();
            PUKPol puk = sess.createPUKPolicy("PUK",
                    PassphraseFormat.NUMERIC,
                    (short) 3 /* retryLimit */,
                    good_puk /* puk */);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    pg,
                    4 /* minLength */,
                    8 /* maxLength */,
                    pin_retry/* retryLimit */,
                    puk /* pukPolicy */);

            GenKey key1 = sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    s_pin /* pin_value */,
                    pinPolicy /* pinPolicy */,
                    AppUsage.SIGNATURE).setCertificate(cn());
            try {
                sess.createKey("Key.2",
                        KeyAlgorithms.RSA1024,
                        a_pin /* pin_value */,
                        pinPolicy /* pinPolicy */,
                        AppUsage.AUTHENTICATION).setCertificate(cn());
                assertTrue("Bad combo " + pg + s_pin + a_pin + e_pin, pg == Grouping.NONE ||
                        (pg == Grouping.SHARED && sa) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && !sa) || (pg == Grouping.UNIQUE && !sa));
            } catch (SKSException e) {
                assertTrue("Bad combo " + pg + s_pin + a_pin + e_pin, (pg == Grouping.SHARED && !sa) ||
                        (pg == Grouping.SIGNATURE_PLUS_STANDARD && sa) || (pg == Grouping.UNIQUE && sa));
                continue;
            }
            try {
                sess.createKey("Key.3",
                        KeyAlgorithms.RSA1024,
                        e_pin /* pin_value */,
                        pinPolicy /* pinPolicy */,
                        AppUsage.ENCRYPTION).setCertificate(cn());
                assertTrue("Bad combo " + pg + s_pin + a_pin + e_pin, pg == Grouping.NONE ||
                        (pg == Grouping.SHARED && sa && ae) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && !sa && ae && !se) || (pg == Grouping.UNIQUE && !sa && !ae && !se));
            } catch (SKSException e) {
                assertTrue("Bad combo " + pg + s_pin + a_pin + e_pin, (pg == Grouping.SHARED &&
                        (!sa || !ae)) || (pg == Grouping.SIGNATURE_PLUS_STANDARD && (sa || !ae || se)) || (pg == Grouping.UNIQUE && (sa || ae || se)));
                continue;
            }
            GenKey key4 = sess.createKey("Key.4",
                    KeyAlgorithms.RSA1024,
                    s_pin /* pin_value */,
                    pinPolicy /* pinPolicy */,
                    AppUsage.SIGNATURE).setCertificate(cn());
            sess.createKey("Key.5",
                    KeyAlgorithms.RSA1024,
                    e_pin /* pin_value */,
                    pinPolicy /* pinPolicy */,
                    AppUsage.ENCRYPTION).setCertificate(cn());
            sess.closeSession();
            key4.changePIN(s_pin, other_pin);
            try {
                key1.signData(AsymSignatureAlgorithms.RSA_SHA256, other_pin, TEST_STRING);
            } catch (SKSException e) {
                assertTrue("None does not distribute PINs", pg == Grouping.NONE);
            }
        }
    }

    public String cn() {
        return "CN=" + _name.getMethodName();
    }

    @Test
    public void test1() throws Exception {
        new ProvSess(device).closeSession();
        try {
            ProvSess.override_server_ephemeral_key_algorithm = KeyAlgorithms.BRAINPOOL_P_256;
            new ProvSess(device).closeSession();
        } catch (Exception e) {
            assertFalse("BC", bc_loaded);
        }
        ProvSess.override_server_ephemeral_key_algorithm = null;
    }

    @Test
    public void test2() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        try {
            sess.closeSession();
            fail("Should have thrown an exception");
        } catch (SKSException e) {
            checkException(e, "Unreferenced object \"" + SecureKeyStore.VAR_ID + "\" : PIN");
        }
    }

    @Test
    public void test3() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        sess.createPUKPolicy("PUK",
                PassphraseFormat.NUMERIC,
                (short) 3 /* retryLimit*/,
                "012355" /* puk */);
        try {
            sess.closeSession();
            fail("Shouldn't happen");
        } catch (SKSException e) {

        }
    }

    @Test
    public void test4() throws Exception {
        ProvSess sess = new ProvSess(device);
        PUKPol puk_pol = sess.createPUKPolicy("PUK",
                PassphraseFormat.NUMERIC,
                (short) 3 /* retryLimit*/,
                "012355" /* puk */);
        sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                puk_pol /* pukPolicy */);
        try {
            sess.closeSession();
        } catch (SKSException e) {
            checkException(e, "Unreferenced object \"" + SecureKeyStore.VAR_ID + "\" : PIN");
        }
    }

    @Test
    public void test5() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION);
        try {
            sess.closeSession();
        } catch (SKSException e) {
            checkException(e, "Missing \"setCertificatePath\" for: Key.1");
        }
        sess = new ProvSess(device);
        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    "1234" /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION);
            fail("PIN without policy");
        } catch (SKSException e) {
            checkException(e, "\"" + SecureKeyStore.VAR_PIN_VALUE + "\" expected to be empty");
        }
    }

    @Test
    public void test6() throws Exception {
        ProvSess sess = new ProvSess(device);
        int i = 1;
        for (KeyAlgorithms key_algorithm : KeyAlgorithms.values()) {
            boolean doit = false;
            if (!bc_loaded && key_algorithm == KeyAlgorithms.BRAINPOOL_P_256) {
                continue;
            }
            if (key_algorithm.isMandatorySksAlgorithm()) {
                doit = true;
            } else {
                for (String algorithm : device.device_info.getSupportedAlgorithms()) {
                    if (key_algorithm.getAlgorithmId(AlgorithmPreferences.SKS).equals(algorithm)) {
                        doit = true;
                        break;
                    }
                }
            }
            if (doit) {
                sess.setKeyParameters((key_algorithm.isRSAKey() && key_algorithm.hasParameters()) ?
                        new byte[]{0, 0, 0, 3} : null);
                sess.createKey("Key." + i++,
                            key_algorithm,
                            null /* pin_value */,
                            null /* pinPolicy */,
                            AppUsage.AUTHENTICATION).setCertificate(cn());
            }
        }
        sess.closeSession();
    }

    @Test
    public void test7() throws Exception {
        retryCountTest(SecureKeyStore.MAX_RETRY_LIMIT, true, true);
        retryCountTest(0, true, false);
        retryCountTest(SecureKeyStore.MAX_RETRY_LIMIT + 1, false, false);
        retryCountTest(-1, false, false);
    }

    @Test
    public void test8() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();

    }

    @Test
    public void test9() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        int keyHandle = device.sks.getKeyHandle(sess.provisioning_handle, "Key.1");
        assertTrue("Key Handle", keyHandle == key.keyHandle);
        sess.closeSession();
        byte[] result = key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, null, TEST_STRING);
        SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, key.getPublicKey());
        verify.update(TEST_STRING);
        assertTrue("Bad signature", verify.verify(result));
        try {
            key.changePIN("1274", "3421");
            fail("Should bomb since this has no pin");
        } catch (SKSException e) {
            checkException(e, "Redundant authorization information for key #");
        }
        try {
            device.sks.getKeyHandle(sess.provisioning_handle, "Key.1");
            fail("No such session");
        } catch (SKSException e) {
            sessionNotOpenCheck(e);
        }
    }

    @Test
    public void test10() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA2048,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue("Must be 0", key.getKeyProtectionInfo().getKeyBackup() == 0);

        byte[] result = key.signData(AsymSignatureAlgorithms.RSA_SHA256, null, TEST_STRING);
        SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA256, key.getPublicKey());
        verify.update(TEST_STRING);
        assertTrue("Bad signature", verify.verify(result));

        result = key.signData(AsymSignatureAlgorithms.RSA_SHA512, null, TEST_STRING);
        verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA512, key.getPublicKey());
        verify.update(TEST_STRING);
        assertTrue("Bad signature", verify.verify(result));
    }

    @Test
    public void test11() throws Exception {
        ProvSess sess = new ProvSess(device);
        PINstress(sess);
    }

    @Test
    public void test12() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.makePINsServerDefined();
        PINstress(sess);
    }

    @Test
    public void test13() throws Exception {
        assertTrue(PUKCheck(PassphraseFormat.ALPHANUMERIC, "AB123"));
        assertTrue(PUKCheck(PassphraseFormat.NUMERIC, "1234"));
        assertTrue(PUKCheck(PassphraseFormat.STRING, "azAB13.\n"));
        assertTrue(PUKCheck(PassphraseFormat.BINARY, "12300234FF"));
        StringBuilder long_puk = new StringBuilder();
        for (int i = 0; i < SecureKeyStore.MAX_LENGTH_PIN_PUK; i++) {
            long_puk.append((char) ('0' + i % 10));
        }
        assertTrue(PUKCheck(PassphraseFormat.NUMERIC, long_puk.toString()));

        assertFalse(PUKCheck(PassphraseFormat.ALPHANUMERIC, ""));  // too short
        assertFalse(PUKCheck(PassphraseFormat.ALPHANUMERIC, "ab123"));  // Lowercase
        assertFalse(PUKCheck(PassphraseFormat.NUMERIC, "AB1234"));      // Alpha
        assertFalse(PUKCheck(PassphraseFormat.NUMERIC, long_puk.append('4').toString()));

        assertTrue(PINCheck(PassphraseFormat.ALPHANUMERIC, null, "AB123"));
        assertTrue(PINCheck(PassphraseFormat.NUMERIC, null, "1234"));
        assertTrue(PINCheck(PassphraseFormat.STRING, null, "azAB13.\n"));
        assertTrue(PINCheck(PassphraseFormat.BINARY, null, "12300234FF"));

        assertFalse(PINCheck(PassphraseFormat.ALPHANUMERIC, null, "ab123"));  // Lowercase
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, null, "AB1234"));      // Alpha

        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1234"));      // Up seq
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "8765"));      // Down seq
        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1235"));      // No seq
        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE}, "1345"));      // No seq

        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "1232"));      // No two in row
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "11345"));      // Two in a row
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.TWO_IN_A_ROW}, "13455"));      // Two in a row

        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "11232"));      // No two in row
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "111345"));      // Three in a row
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.THREE_IN_A_ROW}, "134555"));      // Three in a row

        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1235"));      // No seq or three in a row
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "6789"));      // Seq
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.SEQUENCE, PatternRestriction.THREE_IN_A_ROW}, "1115"));      // Three in a row

        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1476"));      // Bad combo
        assertFalse(PINCheck(PassphraseFormat.BINARY, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "12300234FF"));      // Bad combo

        assertTrue(PINCheck(PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZ."));
        assertTrue(PINCheck(PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "AB34"));

        assertFalse(PINCheck(PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2aZA"));  // Non alphanum missing
        assertFalse(PINCheck(PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "a.jZ"));  // Number missing
        assertFalse(PINCheck(PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2 ZA"));  // Lowercase missing
        assertFalse(PINCheck(PassphraseFormat.STRING, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "2a 6"));  // Uppercase missing

        assertFalse(PINCheck(PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "ABCK")); // Missing number
        assertFalse(PINCheck(PassphraseFormat.ALPHANUMERIC, new PatternRestriction[]{PatternRestriction.MISSING_GROUP}, "1235")); // Missing alpha

        assertTrue(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1345"));
        assertFalse(PINCheck(PassphraseFormat.NUMERIC, new PatternRestriction[]{PatternRestriction.REPEATED}, "1315"));  // Two of same

        assertTrue(PINGroupCheck(true, Grouping.NONE));
        assertTrue(PINGroupCheck(false, Grouping.NONE));
        assertTrue(PINGroupCheck(true, Grouping.SHARED));
        assertFalse(PINGroupCheck(false, Grouping.SHARED));
        assertFalse(PINGroupCheck(true, Grouping.UNIQUE));
        assertTrue(PINGroupCheck(false, Grouping.UNIQUE));
        assertFalse(PINGroupCheck(true, Grouping.SIGNATURE_PLUS_STANDARD));
        assertTrue(PINGroupCheck(false, Grouping.SIGNATURE_PLUS_STANDARD));
    }

    @Test
    public void test14() throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        sess2.postDeleteKey(key1);
        assertTrue("Ownership error", key2.getUpdatedKeyInfo().getProvisioningHandle() == sess.provisioning_handle);
        assertTrue("Missing key, deletes MUST only be performed during session close", key1.exists());
        sess2.closeSession();
        assertFalse("Key was not deleted", key1.exists());
        assertTrue("Ownership error", key2.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertFalse("Managed sessions MUST be deleted", sess.exists());
    }

    @Test
    public void test15() throws Exception {
        for (int i = 0; i < 2; i++) {
            boolean updatable = i == 0;
            ProvSess sess = new ProvSess(device, updatable ? new Integer(0) : null);
            GenKey key1 = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            assertTrue(sess.exists());
            ProvSess sess2 = new ProvSess(device);
            try {
                sess2.postDeleteKey(key1);
                assertTrue("Only OK for updatable", updatable);
            } catch (SKSException e) {
                assertFalse("Only OK for non-updatable", updatable);
                checkException(e, "Key # belongs to a non-updatable provisioning session");
            }
            assertTrue("Missing key, deletes MUST only be performed during session close", key1.exists());
            try {
                sess2.closeSession();
                assertTrue("Ok for updatable", updatable);
            } catch (SKSException e) {
                checkException(e, "No such provisioning session: " + sess2.provisioning_handle);
            }
            assertTrue("Key was not deleted", key1.exists() ^ updatable);
            assertTrue("Managed sessions MUST be deleted", sess.exists() ^ updatable);
        }
    }

    @Test
    public void test16() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        key1.deleteKey(null);
        assertFalse("Key was not deleted", key1.exists());
        assertTrue("Key did not exist", key2.exists());
    }

    @Test
    public void test17() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        key1.deleteKey(null);
        assertFalse("Key was not deleted", key1.exists());
    }

    @Test
    public void test18() throws Exception {
        updateTest(AppUsage.AUTHENTICATION);
        updateTest(AppUsage.SIGNATURE);
    }

    @Test
    public void test19() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device, 0);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key2 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        key2.postUpdateKey(key1);
        sess2.closeSession();
        assertTrue("Key should exist even after update", key1.exists());
        assertFalse("Key has been used and should be removed", key2.exists());
        assertTrue("Ownership error", key1.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertFalse("Managed sessions MUST be deleted", sess.exists());
        try {
            key1.signData(AsymSignatureAlgorithms.ECDSA_SHA256, "bad", TEST_STRING);
            fail("Bad PIN should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        try {
            byte[] result = key1.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, key2.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature", verify.verify(result));
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
    }

    @Test
    public void test20() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        PINPol pinPolicy = sess2.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key2 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        try {
            key2.postUpdateKey(key1);
            fail("No PINs on update keys please");
        } catch (SKSException e) {
            checkException(e, "Updated/cloned keys must not define PIN protection");
        }
        sess2 = new ProvSess(device);
        pinPolicy = sess2.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        key2 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        try {
            key2.postCloneKey(key1);
            fail("No PINs on clone keys please");
        } catch (SKSException e) {
            checkException(e, "Updated/cloned keys must not define PIN protection");
        }
    }

    @Test
    public void test21() throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key2 = sess2.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key3 = sess2.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        key2.postUpdateKey(key1);
        try {
            key3.postUpdateKey(key1);
            fail("Multiple updates of the same key");
        } catch (SKSException e) {
            checkException(e, "Multiple updates of key #");
        }
    }

    @Test
    public void test22() throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key3 = sess2.createKey("Key.3",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        key3.postUpdateKey(key1);
        try {
            key3.postUpdateKey(key2);
            fail("Multiple updates using the same key");
        } catch (SKSException e) {
            checkException(e, "New key used for multiple operations: Key.3");
        }
    }

    @Test
    public void test23() throws Exception {
        testCloning(Grouping.SHARED, AppUsage.AUTHENTICATION);
        testCloning(Grouping.SHARED, AppUsage.SIGNATURE);
        testCloning(Grouping.NONE, AppUsage.AUTHENTICATION);
        testCloning(Grouping.UNIQUE, AppUsage.AUTHENTICATION);
    }

    @Test
    public void test24() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device, 0);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        GenKey key3 = sess2.createKey("Key.1",
                KeyAlgorithms.RSA2048,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        key3.postCloneKey(key1);
        sess2.closeSession();
        assertTrue("Old key should exist after clone", key1.exists());
        assertTrue("New key should exist after clone", key2.exists());
        assertTrue("Ownership error", key1.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertTrue("Ownership error", key2.getUpdatedKeyInfo().getProvisioningHandle() == sess2.provisioning_handle);
        assertFalse("Managed sessions MUST be deleted", sess.exists());
        try {
            key3.signData(AsymSignatureAlgorithms.RSA_SHA256, "1111", TEST_STRING);
            fail("Bad PIN should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        try {
            byte[] result = key3.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
            SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA256, key3.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature key3", verify.verify(result));
            result = key1.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            verify = new SignatureWrapper(AsymSignatureAlgorithms.ECDSA_SHA256, key1.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature key1", verify.verify(result));
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
    }

    @Test
    public void test25() throws Exception {
        updateReplace(true);
    }

    @Test
    public void test26() throws Exception {
        updateReplace(false);
    }

    @Test
    public void test27() throws Exception {
        edgeDeleteCase(true);
    }

    @Test
    public void test28() throws Exception {
        edgeDeleteCase(false);
    }

    @Test
    public void test29() throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key1 = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertTrue(sess.exists());
        ProvSess sess2 = new ProvSess(device);
        sess2.postDeleteKey(key2);
        sks.deleteKey(key1.keyHandle, null);
        sess2.closeSession();
    }

    @Test
    public void test30() throws Exception {
        for (AsymEncryptionAlgorithms algorithm : AsymEncryptionAlgorithms.values()) {
            if (algorithm.isMandatorySksAlgorithm()) {
                rsaEncryptionTest(algorithm);
            }
        }
    }

    @Test
    public void test31() throws Exception {
        String good_pin = "1563";
        String good_puk = "17644";
        short pin_retry = 3;
        ProvSess sess = new ProvSess(device);
        sess.makePINsUserModifiable();
        PUKPol puk_pol = sess.createPUKPolicy("PUK",
                PassphraseFormat.NUMERIC,
                (short) 3 /* retryLimit*/,
                good_puk /* puk */);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                pin_retry/* retryLimit*/,
                puk_pol /* pukPolicy */);

        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.ENCRYPTION).setCertificate(cn());
        sess.closeSession();

        try {
            key.changePIN(good_pin, "843");
        } catch (SKSException e) {
            checkException(e, "PIN length error");
        }
        key.changePIN(good_pin, good_pin = "8463");

        Cipher cipher = Cipher.getInstance(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getJceName());
        cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
        byte[] enc = cipher.doFinal(TEST_STRING);
        assertTrue("Encryption error", ArrayUtil.compare(device.sks.asymmetricKeyDecrypt(key.keyHandle,
                AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getAlgorithmId(AlgorithmPreferences.SKS),
                null,
                good_pin.getBytes("UTF-8"),
                enc), TEST_STRING));
        for (int i = 1; i <= (pin_retry * 2); i++) {
            try {
                key.asymmetricKeyDecrypt(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5, good_pin + "4", enc);
                fail("PIN error");
            } catch (SKSException e) {

            }
            assertTrue("PIN should be blocked", device.sks.getKeyProtectionInfo(key.keyHandle).isPinBlocked() ^ (i < pin_retry));
        }
        try {
            key.asymmetricKeyDecrypt(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5, good_pin, enc);
            fail("PIN lock error");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        try {
            key.unlockKey(good_puk + "2");
            fail("PUK unlock error");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        key.unlockKey(good_puk);
        assertTrue("Encryption error", ArrayUtil.compare(device.sks.asymmetricKeyDecrypt(key.keyHandle,
                AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getAlgorithmId(AlgorithmPreferences.SKS),
                null,
                good_pin.getBytes("UTF-8"),
                enc), TEST_STRING));
        for (int i = 1; i <= (pin_retry * 2); i++) {
            try {
                key.changePIN(good_pin + "2", good_pin);
                fail("PIN error");
            } catch (SKSException e) {

            }
            assertTrue("PIN should be blocked", device.sks.getKeyProtectionInfo(key.keyHandle).isPinBlocked() ^ (i < pin_retry));
        }
        try {
            key.setPIN(good_puk + "2", good_pin);
            fail("PUK error");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
        }
        key.setPIN(good_puk, good_pin + "2");
        assertTrue("Encryption error", ArrayUtil.compare(key.asymmetricKeyDecrypt(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5,
                good_pin + "2",
                enc),
                TEST_STRING));
    }

    @Test
    public void test32() throws Exception {
        String good_pin = "1563";
        String good_puk = "234567";
        for (int i = 0; i < 4; i++) {
            boolean modifiable = i % 2 != 0;
            boolean have_puk = i > 1;

            ProvSess sess = new ProvSess(device);
            if (modifiable) {
                sess.makePINsUserModifiable();
            }
            PUKPol puk = have_puk ? sess.createPUKPolicy("PUK",
                    PassphraseFormat.NUMERIC,
                    (short) 3 /* retryLimit*/,
                    good_puk /* puk */)

                    : null;
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    puk /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            try {
                key.changePIN(good_pin, "8437");
                assertTrue("Modifiable", modifiable);
            } catch (SKSException e) {
                assertFalse("Non-modifiable", modifiable);
                checkException(e, "PIN for key # is not user modifiable");
            }
            try {
                key.setPIN(good_puk, "8437");
                assertTrue("Non modifiable with set PIN", have_puk);
            } catch (SKSException e) {
                checkException(e, have_puk ? "PIN for key # is not user modifiable" : "Key # has no PUK");
            }
        }
    }

    @Test
    public void test33() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        try {
            device.sks.exportKey(key.keyHandle, new byte[0]);
            fail("Shouldn't export");
        } catch (SKSException e) {
            assertTrue("Wrong return code", e.getError() == SKSException.ERROR_NOT_ALLOWED);
        }
    }

    @Test
    public void test34() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.NONE.getSksValue());
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        try {
            KeyProtectionInfo kpi = key.getKeyProtectionInfo();
            assertTrue("No flags should be set", kpi.getKeyBackup() == 0);
            device.sks.exportKey(key.keyHandle, null);
            kpi = key.getKeyProtectionInfo();
            assertTrue("EXPORTED must be set", kpi.getKeyBackup() == KeyProtectionInfo.KEYBACKUP_EXPORTED);
        } catch (SKSException e) {
            fail("Should export");
        }
    }

    @Test
    public void test35() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PIN.getSksValue());
        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    null /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            fail("Missing PIN");
        } catch (SKSException e) {
            checkException(e, "Protection object lacks a PIN or PUK object");
        }
    }

    @Test
    public void test36() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PIN.getSksValue());
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();

        try {
            device.sks.exportKey(key.keyHandle, new byte[0]);
            fail("Bad PIN should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
            assertTrue("PIN Error count", key.getKeyProtectionInfo().getPinErrorCount() == 1);
        }
        try {
            device.sks.exportKey(key.keyHandle, good_pin.getBytes("UTF-8"));
            assertTrue("PIN Error count", key.getKeyProtectionInfo().getPinErrorCount() == 0);
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
    }

    @Test
    public void test37() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PUK.getSksValue());
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    good_pin /* pin_value */,
                    pinPolicy /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            fail("No PUK");
        } catch (SKSException e) {
            checkException(e, "Protection object lacks a PIN or PUK object");
        }
    }

    @Test
    public void test38() throws Exception {
        String good_pin = "1563";
        String good_puk = "17644";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PUK.getSksValue());
        PUKPol puk_pol = sess.createPUKPolicy("PUK",
                PassphraseFormat.NUMERIC,
                (short) 5 /* retryLimit*/,
                good_puk /* puk */);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                puk_pol /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        assertFalse("Not asymmetric key", device.sks.getKeyAttributes(key.keyHandle).isSymmetricKey());
        try {
            device.sks.exportKey(key.keyHandle, new byte[0]);
            fail("Bad PUK should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
            assertTrue("PUK Error count", key.getKeyProtectionInfo().getPukErrorCount() == 1);
            assertTrue("PIN Error count", key.getKeyProtectionInfo().getPinErrorCount() == 0);
        }
        try {
            device.sks.exportKey(key.keyHandle, good_pin.getBytes("UTF-8"));
            fail("PIN should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
            assertTrue("PUK Error count", key.getKeyProtectionInfo().getPukErrorCount() == 2);
        }
        try {
            device.sks.exportKey(key.keyHandle, good_puk.getBytes("UTF-8"));
            assertTrue("PUK Error count", key.getKeyProtectionInfo().getPukErrorCount() == 0);
        } catch (SKSException e) {
            fail("Good PUK should work");
        }
    }

    @Test
    public void test39() throws Exception {
        for (AppUsage keyUsage : AppUsage.values()) {
            byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 6};
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    keyUsage,
                    new String[]{MACAlgorithms.HMAC_SHA256.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
            key.setSymmetricKey(symmetricKey);
            sess.closeSession();
            assertTrue("IMPORTED must be set", key.getKeyProtectionInfo().getKeyBackup() == KeyProtectionInfo.KEYBACKUP_IMPORTED);
        }
    }

    @Test
    public void test40() throws Exception {
        String good_pin = "1563";
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 6};
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION,
                new String[]{MACAlgorithms.HMAC_SHA256.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        key.setSymmetricKey(symmetricKey);
        sess.closeSession();
        assertTrue("Not symmetric key", device.sks.getKeyAttributes(key.keyHandle).isSymmetricKey());
        byte[] result = key.performHMAC(MACAlgorithms.HMAC_SHA256, good_pin, TEST_STRING);
        assertTrue("HMAC error", ArrayUtil.compare(result, MACAlgorithms.HMAC_SHA256.digest(symmetricKey, TEST_STRING)));
        try {
            sess.sks.performHmac(key.keyHandle,
                    MACAlgorithms.HMAC_SHA512.getAlgorithmId(AlgorithmPreferences.SKS),
                    null,
                    good_pin.getBytes("UTF-8"),
                    TEST_STRING);
            fail("Algorithm not allowed");
        } catch (SKSException e) {
        }
        try {
            sess.sks.performHmac(key.keyHandle,
                    SymEncryptionAlgorithms.AES128_CBC.getAlgorithmId(AlgorithmPreferences.SKS),
                    null,
                    good_pin.getBytes("UTF-8"), TEST_STRING);
            fail("Algorithm not allowed");
        } catch (SKSException e) {
        }
    }

    @Test
    public void test41() throws Exception {
        for (SymEncryptionAlgorithms sym_enc : SymEncryptionAlgorithms.values()) {
            byte[] data = TEST_STRING;
            if (sym_enc.needsPadding()) {
                data = new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
            }
            int keyLength = sym_enc.getKeyLength();
            if (keyLength == 0) {
                keyLength = 16;
            }
            byte[] symmetricKey = new byte[keyLength];
            new SecureRandom().nextBytes(symmetricKey);
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = null;
            try {
                key = sess.createKey("Key.1",
                        KeyAlgorithms.NIST_P_256,
                        good_pin /* pin_value */,
                        pinPolicy,
                        AppUsage.AUTHENTICATION,
                        new String[]{sym_enc.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
                key.setSymmetricKey(symmetricKey);
            } catch (SKSException e) {
                assertFalse("Should not throw", sym_enc.isMandatorySksAlgorithm());
                checkException(e, "Unsupported algorithm: " + sym_enc.getAlgorithmId(AlgorithmPreferences.SKS));
                continue;
            }
            sess.closeSession();
            byte[] iv_val = new byte[16];
            new SecureRandom().nextBytes(iv_val);
            byte[] result = key.symmetricKeyEncrypt(sym_enc,
                    true,
                    sym_enc.needsIv() && !sym_enc.internalIv() ? iv_val : null,
                    good_pin,
                    data);
            byte[] res2 = result.clone();
            Cipher crypt = Cipher.getInstance(sym_enc.getJceName());
            if (sym_enc.needsIv()) {
                if (sym_enc.internalIv()) {
                    byte[] temp = new byte[result.length - 16];
                    System.arraycopy(res2, 0, iv_val, 0, 16);
                    System.arraycopy(res2, 16, temp, 0, temp.length);
                    res2 = temp;
                }
                crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmetricKey, "AES"), new IvParameterSpec(iv_val));
            } else {
                crypt.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(symmetricKey, "AES"));
            }
            assertTrue("encrypt error", ArrayUtil.compare(res2, crypt.doFinal(data)));
            assertTrue("decrypt error", ArrayUtil.compare(data, key.symmetricKeyEncrypt(sym_enc,
                    false,
                    sym_enc.needsIv() && !sym_enc.internalIv() ? iv_val : null,
                    good_pin,
                    result)));
            try {
                key.symmetricKeyEncrypt(sym_enc,
                        true,
                        sym_enc.needsIv() && !sym_enc.internalIv() ? null : iv_val,
                        good_pin,
                        data);
                fail("Incorrect IV must fail");
            } catch (SKSException e) {

            }
        }
    }

    @Test
    public void test42() throws Exception {
        for (MACAlgorithms hmac : MACAlgorithms.values()) {
            byte[] data = TEST_STRING;
            byte[] symmetricKey = new byte[20];
            new SecureRandom().nextBytes(symmetricKey);
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = null;
            try {
                key = sess.createKey("Key.1",
                        KeyAlgorithms.NIST_P_256,
                        good_pin /* pin_value */,
                        pinPolicy,
                        AppUsage.AUTHENTICATION,
                        new String[]{hmac.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
                key.setSymmetricKey(symmetricKey);
            } catch (SKSException e) {
                assertFalse("Should not throw", hmac.isMandatorySksAlgorithm());
                checkException(e, "Unsupported algorithm: " + hmac.getAlgorithmId(AlgorithmPreferences.SKS));
                continue;
            }
            sess.closeSession();
            byte[] result = key.performHMAC(hmac, good_pin, data);
            assertTrue("HMAC error", ArrayUtil.compare(result, hmac.digest(symmetricKey, data)));
        }
    }

    @Test
    public void test43() throws Exception {
        String good_pin = "1563";
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6};  // 15 bytes only
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION,
                new String[]{SymEncryptionAlgorithms.AES128_CBC.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        try {
            key.setSymmetricKey(symmetricKey);
            sess.closeSession();
            fail("Wrong key size");
        } catch (SKSException e) {
            checkException(e, "Key Key.1 has wrong size (15) for algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        }
    }

    @Test
    public void test44() throws Exception {
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 6, 54, -3};
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PIN.getSksValue());
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.AUTHENTICATION,
                new String[]{SecureKeyStore.ALGORITHM_NONE}).setCertificate(cn());
        key.setSymmetricKey(symmetricKey);
        sess.closeSession();
        try {
            device.sks.exportKey(key.keyHandle, new byte[0]);
            fail("Bad PIN should not work");
        } catch (SKSException e) {
            assertTrue("Auth error", e.getError() == SKSException.ERROR_AUTHORIZATION);
        }
        try {
            assertTrue("Wrong key", ArrayUtil.compare(symmetricKey, device.sks.exportKey(key.keyHandle, good_pin.getBytes("UTF-8"))));
        } catch (SKSException e) {
            fail("Good PIN should work");
        }
    }

    @Test
    public void test45() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PIN.getSksValue());
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy /* pinPolicy */,
                AppUsage.AUTHENTICATION,
                new String[]{SymEncryptionAlgorithms.AES128_CBC.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        try {
            sess.closeSession();
            fail("Wrong alg for key");
        } catch (SKSException e) {
            checkException(e, "RSA key Key.1 does not match algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        }
    }

    @Test
    public void test46() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        sess.overrideExportProtection(ExportProtection.PIN.getSksValue());
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);

        sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.ENCRYPTION,
                new String[]{SymEncryptionAlgorithms.AES128_CBC.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        try {
            sess.closeSession();
            fail("Wrong alg for key");
        } catch (SKSException e) {
            checkException(e, "EC key Key.1 does not match algorithm: http://www.w3.org/2001/04/xmlenc#aes128-cbc");
        }
    }

    @Test
    public void test47() throws Exception {
        sessionLimitTest(5, false, true);
        sessionLimitTest(6, false, false);
        sessionLimitTest(6, true, true);
        sessionLimitTest(7, true, false);
        sessionLimitTest(7, false, false);
        sessionLimitTest(8, true, false);
    }

    @Test
    public void test48() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair key_pair = kpg.generateKeyPair();
        String good_pin = "1563";
        for (AppUsage keyUsage : AppUsage.values()) {
            ProvSess sess = new ProvSess(device);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    keyUsage).setCertificate(cn(), key_pair.getPublic());
            key.setPrivateKey(key_pair.getPrivate());
            sess.closeSession();
            assertTrue("IMPORTED must be set", key.getKeyProtectionInfo().getKeyBackup() == KeyProtectionInfo.KEYBACKUP_IMPORTED);
            Cipher cipher = Cipher.getInstance(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5.getJceName());
            cipher.init(Cipher.ENCRYPT_MODE, key.getPublicKey());
            byte[] enc = cipher.doFinal(TEST_STRING);
            assertTrue("Encryption error", ArrayUtil.compare(key.asymmetricKeyDecrypt(AsymEncryptionAlgorithms.RSA_ES_PKCS_1_5,
                    good_pin,
                    enc), TEST_STRING));
            byte[] result = key.signData(AsymSignatureAlgorithms.RSA_SHA256, good_pin, TEST_STRING);
            SignatureWrapper verify = new SignatureWrapper(AsymSignatureAlgorithms.RSA_SHA256, key.getPublicKey());
            verify.update(TEST_STRING);
            assertTrue("Bad signature", verify.verify(result));
            try {
                key.performHMAC(MACAlgorithms.HMAC_SHA256, good_pin, TEST_STRING);
                fail("Sym key!");
            } catch (SKSException e) {
                checkException(e, "Asymmetric key # is incompatible with: http://www.w3.org/2001/04/xmldsig-more#hmac-sha256");
            }
        }
    }

    @Test
    public void test49() throws Exception {
        create3Keys("1111", "1111", "1111");
        create3Keys("1111", "2222", "3333");
        create3Keys("1111", "2222", "2222");
        create3Keys("1111", "1111", "2222");
    }

    @Test
    public void test50() throws Exception {
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 6};
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.ENCRYPTION,
                new String[]{SymEncryptionAlgorithms.AES192_CBC.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        try {
            key.setSymmetricKey(symmetricKey);
            sess.closeSession();
            fail("Wrong length");
        } catch (SKSException e) {
            checkException(e, "Key Key.1 has wrong size (16) for algorithm: http://www.w3.org/2001/04/xmlenc#aes192-cbc");
        }
    }

    @Test
    public void test51() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.ENCRYPTION).setCertificate(cn());
        sess.closeSession();
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec("secp256r1");
        generator.initialize(eccgen, new SecureRandom());
        KeyPair key_pair = generator.generateKeyPair();
        byte[] z = device.sks.keyAgreement(key.keyHandle,
                SecureKeyStore.ALGORITHM_ECDH_RAW,
                null,
                good_pin.getBytes("UTF-8"),
                (ECPublicKey) key_pair.getPublic());
        KeyAgreement key_agreement = KeyAgreement.getInstance("ECDH");
        key_agreement.init(key_pair.getPrivate());
        key_agreement.doPhase(key.getPublicKey(), true);
        byte[] Z = key_agreement.generateSecret();
        assertTrue("DH fail", ArrayUtil.compare(z, Z));
    }

    @Test
    public void test52() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.ENCRYPTION).setCertificate(cn());
        sess.closeSession();
        try {
            key.setSymmetricKey(new byte[]{0, 1, 2, 3, 4, 5, 6, 7, 8, 9});
            fail("Not open key");
        } catch (SKSException e) {
            checkException(e, "Key # not belonging to open session");
        }
    }

    @Test
    public void test53() throws Exception {
        for (int i = 0; i < 2; i++) {
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device, i);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            lockECKey(key, good_pin);
            ProvSess sess2 = new ProvSess(device);
            try {
                sess2.postUnlockKey(key);
                assertTrue("Bad kmk should throw", i == 0);
            } catch (SKSException e) {
                assertFalse("Good kmk should not throw", i == 0);
                checkException(e, "\"" + SecureKeyStore.VAR_AUTHORIZATION + "\" signature did not verify for key #");
            }
            try {
                sess2.closeSession();
                assertTrue("Bad kmk should throw", i == 0);
            } catch (SKSException e) {
                assertFalse("Good kmk should not throw", i == 0);
            }
            try {
                key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
                assertTrue("Bad kmk should throw", i == 0);
            } catch (SKSException e) {
                assertFalse("Good kmk should not throw", i == 0);
                authorizationErrorCheck(e);
            }
        }
    }

    @Test
    public void test54() throws Exception {
        for (int i = 0; i < 2; i++) {
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device, 0);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            lockECKey(key, good_pin);
            ProvSess sess2 = new ProvSess(device);
            GenKey new_key = sess2.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            if (i == 0) new_key.postUpdateKey(key);
            sess2.postUnlockKey(key);
            if (i == 1) new_key.postUpdateKey(key);
            sess2.closeSession();
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            assertFalse("taken", new_key.exists());
        }
    }

    @Test
    public void test55() throws Exception {
        for (int i = 0; i < 2; i++) {
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device, 0);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            lockECKey(key, good_pin);
            ProvSess sess2 = new ProvSess(device);
            GenKey new_key = sess2.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            if (i == 0) new_key.postCloneKey(key);
            sess2.postUnlockKey(key);
            if (i == 1) new_key.postCloneKey(key);
            sess2.closeSession();
            new_key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
        }
    }

    @Test
    public void test56() throws Exception {
        for (int i = 0; i < 6; i++) {
            String good_pin = "1563";
            ProvSess sess = new ProvSess(device, (short) 50, 0, i < 2, null);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            lockECKey(key, good_pin);
            ProvSess sess2 = new ProvSess(device, (short) 50, 0, i < 2 || i > 3, null);
            GenKey new_key = sess2.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null /* pinPolicy */,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            try {
                if (i % 2 == 0) new_key.postCloneKey(key);
                sess2.postUnlockKey(key);
                if (i % 2 == 1) new_key.postCloneKey(key);
                sess2.closeSession();
                assertTrue("Shouldn't", i < 4);
                new_key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
                key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
            } catch (SKSException e) {
                checkException(e, "Inconsistent use of the \"" + SecureKeyStore.VAR_PRIVACY_ENABLED + "\" attribute for key #");
            }
        }
    }

    @Test
    public void test57() throws Exception {
        algOrder(new String[]{AsymSignatureAlgorithms.RSA_SHA512.getAlgorithmId(AlgorithmPreferences.SKS),
                        AsymSignatureAlgorithms.RSA_SHA512.getAlgorithmId(AlgorithmPreferences.SKS)},
                AsymSignatureAlgorithms.RSA_SHA512.getAlgorithmId(AlgorithmPreferences.SKS));
        algOrder(new String[]{AsymSignatureAlgorithms.RSA_SHA512.getAlgorithmId(AlgorithmPreferences.SKS),
                        AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS)},
                AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS));
        algOrder(new String[]{AsymSignatureAlgorithms.RSA_SHA256.getAlgorithmId(AlgorithmPreferences.SKS),
                        AsymSignatureAlgorithms.RSA_SHA512.getAlgorithmId(AlgorithmPreferences.SKS)},
                null);
    }

    @Test
    public void test58() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec("secp256r1");
        generator.initialize(eccgen, new SecureRandom());
        KeyPair key_pair = generator.generateKeyPair();
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        key.setPrivateKey(key_pair.getPrivate());
        GenKey key2 = sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificatePath(key.getCertificatePath());
        key2.setPrivateKey(key_pair.getPrivate());
        try {
            sess.closeSession();
            fail("Not allowed");
        } catch (SKSException e) {
            checkException(e, "Duplicate certificate in \"setCertificatePath\" for: Key.1");
        }
        sess = new ProvSess(device);
        key = sess.createKey("Key.3",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        key.setPrivateKey(key_pair.getPrivate());
        sess.closeSession();
        sess = new ProvSess(device);
        key2 = sess.createKey("Key.4",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificatePath(key.getCertificatePath());
        key2.setPrivateKey(key_pair.getPrivate());
        try {
            sess.closeSession();
            fail("Not allowed");
        } catch (SKSException e) {
            checkException(e, "Duplicate certificate in \"setCertificatePath\" for: Key.4");
        }
        sess = new ProvSess(device, 0);
        key = sess.createKey("Key.3",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        key.setPrivateKey(key_pair.getPrivate());
        sess.closeSession();
        ProvSess sess2 = new ProvSess(device);
        GenKey new_key = sess2.createKey("Key.4",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificatePath(key.getCertificatePath());
        new_key.setPrivateKey(key_pair.getPrivate());
        new_key.postUpdateKey(key);
        sess2.closeSession();
        sess = new ProvSess(device, 0);
        key = sess.createKey("Key.3",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        key.setPrivateKey(key_pair.getPrivate());
        sess.closeSession();
        sess2 = new ProvSess(device);
        new_key = sess2.createKey("Key.4",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null /* pinPolicy */,
                AppUsage.AUTHENTICATION).setCertificatePath(key.getCertificatePath());
        new_key.setPrivateKey(key_pair.getPrivate());
        sess2.postDeleteKey(key);
        sess2.closeSession();
    }

    @Test
    public void test59() throws Exception {
        if (tga != null) for (InputMethod inputMethod : InputMethod.values()) {
            String good_pin = DummyTrustedGUIAuthorization.GOOD_TRUSTED_GUI_PIN;
            ProvSess sess = new ProvSess(device);
            sess.setInputMethod(inputMethod);
            PINPol pinPolicy = sess.createPINPolicy("PIN",
                    PassphraseFormat.NUMERIC,
                    EnumSet.noneOf(PatternRestriction.class),
                    Grouping.SHARED,
                    4 /* minLength */,
                    8 /* maxLength */,
                    (short) 3 /* retryLimit*/,
                    null /* pukPolicy */);
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    good_pin /* pin_value */,
                    pinPolicy,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            sess.closeSession();
            key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, inputMethod == InputMethod.TRUSTED_GUI ? null : good_pin, TEST_STRING);
            if (inputMethod == InputMethod.ANY) {
                key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, null, TEST_STRING);
            }
        }
    }

    @Test
    public void test60() throws Exception {
        String good_pin = "1563";
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 8};
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION,
                new String[]{SymEncryptionAlgorithms.AES128_CBC.getAlgorithmId(AlgorithmPreferences.SKS)}).setCertificate(cn());
        key.setSymmetricKey(symmetricKey);
        try {
            key.setSymmetricKey(symmetricKey);
            sess.closeSession();
            fail("Duplicate import");
        } catch (SKSException e) {
            checkException(e, "Mutiple key imports for: Key.1");
        }
    }

    @Test
    public void test61() throws Exception {
        String good_pin = "1563";
        byte[] symmetricKey = {0, 5, 3, 9, 0, 23, 67, 56, 8, 34, -45, 4, 2, 5, 6, 8};
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED, 4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit */,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        key.setSymmetricKey(symmetricKey);
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair key_pair = kpg.generateKeyPair();
            key.setPrivateKey(key_pair.getPrivate());
            sess.closeSession();
            fail("Duplicate import");
        } catch (SKSException e) {
            checkException(e, "Mutiple key imports for: Key.1");
        }
    }

    @Test
    public void test62() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED, 4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit */,
                null /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(1024);
            KeyPair key_pair = kpg.generateKeyPair();
            key.setPrivateKey(key_pair.getPrivate());
            sess.closeSession();
            fail("Mixing RSA and EC is not possible");
        } catch (SKSException e) {
            checkException(e, "RSA/EC mixup between public and private keys for: Key.1");
        }
    }

    @Test
    public void test63() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED, 4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit */,
                null /* pukPolicy */);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair key_pair = kpg.generateKeyPair();
        sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        try {
            sess.closeSession();
            fail("Mismatch");
        } catch (SKSException e) {
            checkException(e, "RSA/EC mixup between public and private keys for: Key.1");
        }
    }

    @Test
    public void test64() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED, 4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit */,
                null /* pukPolicy */);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        KeyPair key_pair = kpg.generateKeyPair();
        sess.createKey("Key.1",
                KeyAlgorithms.RSA1024,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        try {
            sess.closeSession();
            fail("Mismatch");
        } catch (SKSException e) {
            checkException(e, "RSA mismatch between public and private keys for: Key.1");
        }
    }

    @Test
    public void test65() throws Exception {
        String good_pin = "1563";
        ProvSess sess = new ProvSess(device);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                EnumSet.noneOf(PatternRestriction.class),
                Grouping.SHARED, 4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit */,
                null /* pukPolicy */);
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        ECGenParameterSpec eccgen = new ECGenParameterSpec("secp256r1");
        generator.initialize(eccgen, new SecureRandom());
        KeyPair key_pair = generator.generateKeyPair();
        sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
        try {
            sess.closeSession();
            fail("Mismatch");
        } catch (SKSException e) {
            checkException(e, "EC mismatch between public and private keys for: Key.1");
        }
    }

    @Test
    public void test66() throws Exception {
        try {
            new ProvSess(device, 3);
            fail("Bad KMK");
        } catch (SKSException e) {
            checkException(e, "Unsupported RSA key size 512 for: \"" + SecureKeyStore.VAR_KEY_MANAGEMENT_KEY + "\"");
        }
    }

    @Test
    public void test67() throws Exception {
        ProvSess.override_server_ephemeral_key_algorithm = KeyAlgorithms.NIST_B_233;
        try {
            new ProvSess(device);
            fail("Bad server key");
        } catch (SKSException e) {
            checkException(e, "Unsupported EC key algorithm for: \"" + SecureKeyStore.VAR_SERVER_EPHEMERAL_KEY + "\"");
            ProvSess.override_server_ephemeral_key_algorithm = null;
        }
    }

    @Test
    public void test68() throws Exception {
        badKeySpec(KeyAlgorithms.RSA1024.getAlgorithmId(AlgorithmPreferences.SKS), new byte[]{0, 0, 0, 3}, "Unexpected \"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\"");
        badKeySpec(KeyAlgorithms.NIST_P_256.getAlgorithmId(AlgorithmPreferences.SKS), new byte[]{0, 0, 0, 3}, "Unexpected \"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\"");
        badKeySpec("http://badcrypto/snakeoil-1", null, "Unsupported \"" + SecureKeyStore.VAR_KEY_ALGORITHM + "\": http://badcrypto/snakeoil-1");
        boolean supports_var_exp = false;
        for (String algorithm : device.device_info.getSupportedAlgorithms()) {
            if (algorithm.equals(KeyAlgorithms.RSA1024_EXP.getAlgorithmId(AlgorithmPreferences.SKS))) {
                supports_var_exp = true;
                break;
            }
        }
        if (supports_var_exp) {
            badKeySpec(KeyAlgorithms.RSA1024_EXP.getAlgorithmId(AlgorithmPreferences.SKS), null, "Missing \"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\"");
            badKeySpec(KeyAlgorithms.RSA1024_EXP.getAlgorithmId(AlgorithmPreferences.SKS), new byte[]{0, 0, 0, 0, 0, 0, 0, 0, 3}, "\"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\" length error: 9");
            badKeySpec(KeyAlgorithms.RSA1024_EXP.getAlgorithmId(AlgorithmPreferences.SKS), new byte[0], "\"" + SecureKeyStore.VAR_KEY_PARAMETERS + "\" length error: 0");
        }
        ProvSess sess = new ProvSess(device);
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(new RSAKeyGenParameterSpec(1024, BigInteger.valueOf(3)));
        KeyPair key_pair = kpg.generateKeyPair();
        try {
            GenKey key = sess.createKey("Key.1",
                    KeyAlgorithms.RSA1024,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION).setCertificate(cn(), key_pair.getPublic());
            key.setPrivateKey(key_pair.getPrivate());
            sess.closeSession();
            assertTrue("RSA exp match", supports_var_exp);
        } catch (SKSException e) {
            assertFalse("RSA exp mismatch", supports_var_exp);
            checkException(e, "Unsupported RSA exponent value for: Key.1");
        }
    }

    @Test
    public void test69() throws Exception {
        userModifyPINCheck ump = new userModifyPINCheck("A5J0",
                PassphraseFormat.ALPHANUMERIC,
                new PatternRestriction[]{PatternRestriction.SEQUENCE,
                        PatternRestriction.THREE_IN_A_ROW,
                        PatternRestriction.MISSING_GROUP});
        ump.test("a3b4", false);        // Lowercase
        ump.test("A3B4", true);         // OK
        ump.test("A3B453CC", true);     // OK
        ump.test("A3B453CCD", false);   // > 8
        ump.test("A3B", false);         // < 4
        ump.test("CBAG", false);        // Missing group
        ump.test("3684", false);        // Missing group
        ump.test("333A", false);        // Repeat 3
        ump = new userModifyPINCheck("16923",
                PassphraseFormat.NUMERIC,
                new PatternRestriction[]{PatternRestriction.SEQUENCE,
                        PatternRestriction.THREE_IN_A_ROW});
        ump.test("A3B4", false);        // Alpha
        ump.test("1234", false);        // Sequence
        ump.test("8765", false);        // Sequence
        ump.test("1555", false);        // Three in a row
        ump.test("15554", false);       // Three in a row
        ump.test("5554", false);        // Three in a row
        ump.test("1952", true);         // OK
    }

    @Test
    public void test70() throws Exception {
        checkIDObject("", false);
        checkIDObject(" ", false);
        checkIDObject("9", true);
        checkIDObject("h09876543210987654321098765432109", false);
        checkIDObject("h0987654321098765432109876543210", true);
        checkIDObject("#9+/\\@,:_-.;=&%$\"*", true);
        checkIDObject(" I_am_a_bad_name", false);
    }

    @Test
    public void test71() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION);
        try {
            sess.sks.importSymmetricKey(key.keyHandle,
                    new byte[]{0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8},
                    new byte[]{0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8, 0, 5, 6, 8});
            fail("Can't import without EE");
        } catch (SKSException e) {
            checkException(e, "Missing \"setCertificatePath\" for: Key.1");
        }
    }

    @Test
    public void test72() throws Exception {
        String good_pin = "1563";
        String good_puk = "17644";
        ProvSess sess = new ProvSess(device);
        PUKPol puk_pol = sess.createPUKPolicy("PUK",
                PassphraseFormat.NUMERIC,
                (short) 0 /* retryLimit*/,
                good_puk /* puk */);
        PINPol pinPolicy = sess.createPINPolicy("PIN",
                PassphraseFormat.NUMERIC,
                4 /* minLength */,
                8 /* maxLength */,
                (short) 3 /* retryLimit*/,
                puk_pol /* pukPolicy */);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                good_pin /* pin_value */,
                pinPolicy,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        for (int i = 0; i < 3; i++) {
            try {
                key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin + "3", TEST_STRING);
                fail("Bad PIN should not work");
            } catch (SKSException e) {
                authorizationErrorCheck(e);
                assertTrue("PUK Error count", key.getKeyProtectionInfo().getPukErrorCount() == 0);
            }
        }
        KeyProtectionInfo kpi = key.getKeyProtectionInfo();
        assertTrue("Should be PIN blocked", kpi.isPinBlocked());
        assertFalse("Should not be PUK blocked", kpi.isPukBlocked());
        try {
            key.unlockKey(good_puk + "34");
            fail("Bad PUK should not work");
        } catch (SKSException e) {
            authorizationErrorCheck(e);
            assertTrue("PUK Error count", key.getKeyProtectionInfo().getPukErrorCount() == 0);
        }
        assertTrue("Should be PIN blocked", kpi.isPinBlocked());
        assertFalse("Should not be PUK blocked", kpi.isPukBlocked());
        key.unlockKey(good_puk);
        key.signData(AsymSignatureAlgorithms.ECDSA_SHA256, good_pin, TEST_STRING);
    }

    @Test
    public void test73() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        String type = "http://example.com/define";
        byte subType = SecureKeyStore.SUB_TYPE_EXTENSION;
        byte[] extension_data = {1, 4, 6, 8};
        key.addExtension(type, subType, "", extension_data);
        try {
            key.addExtension(type, subType, "", extension_data);
            fail("Duplicate");
        } catch (SKSException e) {
            checkException(e, "Duplicate \"" + SecureKeyStore.VAR_TYPE + "\" : " + type);
        }
        sess = new ProvSess(device);
        key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        type = "http://example.com/define";
        subType = SecureKeyStore.SUB_TYPE_EXTENSION;
        key.addExtension(type, subType, "", extension_data);
        sess.closeSession();
        try {
            device.sks.getExtension(key.keyHandle, type + "@");
            fail("Non-existing");
        } catch (SKSException e) {
            checkException(e, "No such extension: http://example.com/define@ for key #", SKSException.ERROR_OPTION);
        }
        byte[] ext_data = {4, 6, 2, 9, 4};
        extensionTest(SecureKeyStore.SUB_TYPE_EXTENSION, null, ext_data, null);
        extensionTest(SecureKeyStore.SUB_TYPE_EXTENSION, null, new byte[device.device_info.getExtensionDataSize()], null);
        extensionTest(SecureKeyStore.SUB_TYPE_EXTENSION, null, new byte[device.device_info.getExtensionDataSize() + 1], "Extension data exceeds " + device.device_info.getExtensionDataSize() + " bytes");
        extensionTest(SecureKeyStore.SUB_TYPE_ENCRYPTED_EXTENSION, null, ext_data, null);
        extensionTest(SecureKeyStore.SUB_TYPE_LOGOTYPE, null, ext_data, "\"" + SecureKeyStore.VAR_QUALIFIER + "\" length error");
        extensionTest(SecureKeyStore.SUB_TYPE_LOGOTYPE, "image/gif", ext_data, null);
        extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null, ext_data, "\"" + SecureKeyStore.VAR_PROPERTY_BAG + "\" format error: http://example.com/define");
        Property[] props = extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null,
                new byte[]{0, 4, 'n', 'a', 'm', 'e', 0, 0, 5, 'v', 'a', 'l', 'u', 'e'}, null).getProperties();
        assertTrue("Number of props", props.length == 1);
        assertTrue("Prop value", props[0].getName().equals("name") && props[0].getValue().equals("value"));
        extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null,
                new byte[]{0, 4, 'n', 'a', 'm', 'e', 1, 0, 5, 'v', 'a', 'l', 'u', 'e',
                        0, 4, 'l', 'a', 'm', 'e', 0, 0, 5, 'v', 'a', 'l', 'u', 'e'}, null);
        extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null,
                new byte[]{0, 4, 'n', 'a', 'm', 'e', 2, 0, 5, 'v', 'a', 'l', 'u', 'e'}, "\"" + SecureKeyStore.VAR_PROPERTY_BAG + "\" format error: http://example.com/define");
        extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null,
                new byte[]{0, 4, 'n', 'a', 'm', 'e', 0, 5, 'v', 'a', 'l', 'u', 'e'}, "\"" + SecureKeyStore.VAR_PROPERTY_BAG + "\" format error: http://example.com/define");
        extensionTest(SecureKeyStore.SUB_TYPE_PROPERTY_BAG, null,
                new byte[]{0, 4, 'n', 'a', 'm', 'e', 0, 0, 5, 'v', 'a', 'l', 'u', 'e', 's'}, "\"" + SecureKeyStore.VAR_PROPERTY_BAG + "\" format error: http://example.com/define");
    }

    @Test
    public void test74() throws Exception {
        ProvSess sess = new ProvSess(device);
        assertTrue("Signature error",
                ArrayUtil.compare(device.sks.signProvisioningSessionData(sess.provisioning_handle, TEST_STRING),
                        sess.serverSessionSign(TEST_STRING)));
        sess.closeSession();
    }

    @Test
    public void test75() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.failMAC();
        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION);
            fail("MAC");
        } catch (SKSException e) {
            checkException(e, "MAC error");
        }
    }

    @Test
    public void test76() throws Exception {
        ProvSess sess = new ProvSess(device);
        try {
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION).setCertificate(device.device_info.getCryptoDataSize());
            fail("Shouldn't pass");
        } catch (SKSException e) {
            checkException(e, "Certificate for: Key.1 exceeds " + device.device_info.getCryptoDataSize() + " bytes");
        }
    }

    @Test
    public void test77() throws Exception {
        serverSeed(SecureKeyStore.MAX_LENGTH_SERVER_SEED);
        try {
            serverSeed(SecureKeyStore.MAX_LENGTH_SERVER_SEED + 1);
            fail("ServerSeed");
        } catch (SKSException e) {
            checkException(e, "\"" + SecureKeyStore.VAR_SERVER_SEED + "\" length error: " + (SecureKeyStore.MAX_LENGTH_SERVER_SEED + 1));
        }
    }

    @Test
    public void test78() throws Exception {
        ProvSess sess = new ProvSess(device, 0);
        GenKey key = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.createKey("Key.2",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        PublicKey keyManagementKey = sess.server_sess_key.enumerateKeyManagementKeys()[1];  // The new KMK
        byte[] authorization = sess.server_sess_key.generateKeyManagementAuthorization(sess.server_sess_key.enumerateKeyManagementKeys()[0],
                ArrayUtil.add(SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                        keyManagementKey.getEncoded()));
        device.sks.updateKeyManagementKey(sess.provisioning_handle, keyManagementKey, authorization);
        ProvSess sess2 = new ProvSess(device);
        sess2.byPassKMK(1);
        sess2.postDeleteKey(key);
        sess2.closeSession();
    }

    @Test
    public void test79() throws Exception {
        ProvSess sess = new ProvSess(device);
        sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();
        PublicKey keyManagementKey = sess.server_sess_key.enumerateKeyManagementKeys()[1];  // The new KMK
        byte[] authorization = sess.server_sess_key.generateKeyManagementAuthorization(sess.server_sess_key.enumerateKeyManagementKeys()[0],
                ArrayUtil.add(SecureKeyStore.KMK_ROLL_OVER_AUTHORIZATION,
                        keyManagementKey.getEncoded()));
        try {
            device.sks.updateKeyManagementKey(sess.provisioning_handle, keyManagementKey, authorization);
            fail("Not updatable");
        } catch (SKSException e) {
            checkException(e, "Session is not updatable: " + sess.provisioning_handle);
        }
    }

    @Test
    public void test80() throws Exception {
        try {
            ProvSess.override_session_key_algorithm = "http://blah";
            new ProvSess(device);
            fail("Not good");
        } catch (SKSException e) {
            checkException(e, "Unknown \"" + KeyGen2Constants.SESSION_KEY_ALGORITHM_JSON + "\" : " + ProvSess.override_session_key_algorithm);
            ProvSess.override_session_key_algorithm = null;
        }
    }

    @Test
    public void test81() throws Exception {
        ProvSess sess = null;
        try {
            sess = new ProvSess(device);
            sess.override_key_entry_algorithm = "http://somewhere";
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            fail("Not good");
        } catch (SKSException e) {
            checkException(e, "Unknown \"" + KeyGen2Constants.KEY_ENTRY_ALGORITHM_JSON + "\" : " + sess.override_key_entry_algorithm);
        }
    }

    @Test
    public void test82() throws Exception {
        ProvSess sess = new ProvSess(device);
        GenKey ec = sess.createKey("Key.1",
                KeyAlgorithms.NIST_P_256,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        GenKey rsa = sess.createKey("Key.2",
                KeyAlgorithms.RSA2048,
                null /* pin_value */,
                null,
                AppUsage.AUTHENTICATION).setCertificate(cn());
        sess.closeSession();

        for (AsymSignatureAlgorithms alg : AsymSignatureAlgorithms.values()) {
            GenKey tk = alg.isRsa() ? rsa : ec;
            try {
                byte[] result = tk.signData(alg, null, TEST_STRING);
                SignatureWrapper verify = new SignatureWrapper(alg, tk.getPublicKey());
                verify.update(TEST_STRING);
                assertTrue("Bad signature " + alg.getAlgorithmId(AlgorithmPreferences.SKS), verify.verify(result));
            } catch (SKSException e) {
                assertTrue("SKS missing: " + alg.getAlgorithmId(AlgorithmPreferences.SKS), 
                           !alg.isMandatorySksAlgorithm());
                checkException(e, "Unsupported algorithm: " + alg.getAlgorithmId(AlgorithmPreferences.SKS));
            }
        }
    }

    @Test
    public void Test83() throws Exception {
        boolean dev_pin = device.sks.getDeviceInfo().getDevicePinSupport();
        try {
            ProvSess sess = new ProvSess(device);
            sess.devicePinProtected = true;
            sess.createKey("Key.1",
                    KeyAlgorithms.NIST_P_256,
                    null /* pin_value */,
                    null,
                    AppUsage.AUTHENTICATION).setCertificate(cn());
            assertTrue("devPIN", dev_pin);
            sess.closeSession();
        } catch (SKSException e) {
            checkException(e, "Unsupported: \"devicePinProtection\"");
        }
    }
}

/*
 *  Copyright 2006-2021 WebPKI.org (http://webpki.org).
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
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;

import java.security.cert.X509Certificate;

import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAKey;
import java.security.interfaces.RSAPublicKey;

import java.security.spec.ECGenParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;

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
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.SignatureWrapper;
import org.webpki.crypto.HmacAlgorithms;
import org.webpki.crypto.AsymSignatureAlgorithms;

import org.webpki.json.JSONParser;

import org.webpki.util.ArrayUtil;
import org.webpki.util.DebugFormatter;

public class ProvSess {
    
    static X509Certificate[] getCertPath(String json) {
        try {
            return JSONParser.parse(json).getJSONArrayReader().getCertificatePath();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    static final LinkedHashMap<KeyAlgorithms, ECPublicKey> nonSKSTypes = new LinkedHashMap<>();
    
    static void getPublicKey(KeyAlgorithms keyAlgorithm, byte[] publicKey) {
        try {
            ECPublicKey ecPublicKey = 
                    (ECPublicKey) KeyFactory.getInstance("EC").generatePublic(
                            new X509EncodedKeySpec(publicKey));
            nonSKSTypes.put(keyAlgorithm, ecPublicKey);
        } catch (Exception e) {
            if (keyAlgorithm.getECParameterSpec() != null) {
                throw new RuntimeException(e);
            }
        }
    }
    
    static {
        getPublicKey(KeyAlgorithms.BRAINPOOL_P_256, new byte[]
           {(byte)0x30, (byte)0x5A, (byte)0x30, (byte)0x14, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
            (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x09, (byte)0x2B,
            (byte)0x24, (byte)0x03, (byte)0x03, (byte)0x02, (byte)0x08, (byte)0x01, (byte)0x01, (byte)0x07,
            (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04, (byte)0x26, (byte)0x3C, (byte)0x91, (byte)0x3F,
            (byte)0x6B, (byte)0x91, (byte)0x10, (byte)0x6F, (byte)0xE4, (byte)0xA2, (byte)0x2D, (byte)0xA4,
            (byte)0xBB, (byte)0xAB, (byte)0xCE, (byte)0x9E, (byte)0x41, (byte)0x01, (byte)0x0B, (byte)0xB0,
            (byte)0xC3, (byte)0x84, (byte)0xEF, (byte)0x35, (byte)0x0D, (byte)0x66, (byte)0xEE, (byte)0x0C,
            (byte)0xEC, (byte)0x60, (byte)0xB6, (byte)0xF5, (byte)0x54, (byte)0x54, (byte)0x27, (byte)0x2A,
            (byte)0x1D, (byte)0x07, (byte)0x61, (byte)0xB0, (byte)0xC3, (byte)0x01, (byte)0xE8, (byte)0xCB,
            (byte)0x52, (byte)0xF5, (byte)0x03, (byte)0xC1, (byte)0x0C, (byte)0x3F, (byte)0xF0, (byte)0x97,
            (byte)0xCD, (byte)0xC9, (byte)0x45, (byte)0xF3, (byte)0x21, (byte)0xC5, (byte)0xCF, (byte)0x41,
            (byte)0x17, (byte)0xF3, (byte)0x3A, (byte)0xB4});
        getPublicKey(KeyAlgorithms.SECG_K_256, new byte[]
           {(byte)0x30, (byte)0x56, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x07, (byte)0x2A, (byte)0x86,
            (byte)0x48, (byte)0xCE, (byte)0x3D, (byte)0x02, (byte)0x01, (byte)0x06, (byte)0x05, (byte)0x2B,
            (byte)0x81, (byte)0x04, (byte)0x00, (byte)0x0A, (byte)0x03, (byte)0x42, (byte)0x00, (byte)0x04,
            (byte)0xA9, (byte)0xF7, (byte)0xEF, (byte)0x65, (byte)0x26, (byte)0x2F, (byte)0xDB, (byte)0x11,
            (byte)0xE3, (byte)0xDA, (byte)0x7C, (byte)0x9D, (byte)0xDF, (byte)0x1F, (byte)0x2E, (byte)0x32,
            (byte)0x49, (byte)0x99, (byte)0x4B, (byte)0x02, (byte)0x07, (byte)0x02, (byte)0x78, (byte)0x94,
            (byte)0xFF, (byte)0x1C, (byte)0x5A, (byte)0x30, (byte)0xB3, (byte)0x39, (byte)0x44, (byte)0xF4,
            (byte)0x50, (byte)0xBE, (byte)0xC9, (byte)0x6C, (byte)0xAE, (byte)0xE6, (byte)0xA5, (byte)0xC0,
            (byte)0x8B, (byte)0xF9, (byte)0x29, (byte)0x5B, (byte)0xA0, (byte)0x16, (byte)0xC5, (byte)0x36,
            (byte)0xDD, (byte)0xE6, (byte)0xA1, (byte)0x21, (byte)0x6D, (byte)0x80, (byte)0x77, (byte)0xD7,
            (byte)0x5B, (byte)0xC1, (byte)0x32, (byte)0x44, (byte)0xA6, (byte)0x32, (byte)0x06, (byte)0xA9});
    }
    
    static final X509Certificate[] SUBCA_RSA_KEY_2 = getCertPath(

        "[" +
        "  \"MIIDZjCCAk6gAwIBAgICAMgwDQYJKoZIhvcNAQELBQAwRDETMBEGCgmSJomT8ixkARkWA29yZzEWMBQGCgmSJomT8ixkARkW" +
        "BndlYnBraTEVMBMGA1UEAxMMRGVtbyBSb290IENBMB4XDTA1MDcxMDEwMDAwMFoXDTI1MDcxMDA5NTk1OVowQzETMBEGCgmSJomT" +
        "8ixkARkWA29yZzEWMBQGCgmSJomT8ixkARkWBndlYnBraTEUMBIGA1UEAxMLRGVtbyBTdWIgQ0EwggEiMA0GCSqGSIb3DQEBAQUA" +
        "A4IBDwAwggEKAoIBAQCSrWMH7obPRqFHGlLL0tY1_7Mv0K7lA2yESZeEnohUvfd4VgxqCATcZ_9qg4Ya0wBqP9ltUmhPf5M7autO" +
        "45XRLMjtYUeSI5xRlGCTHNThwWSWrVXJAeVNx1tfr41XTOdN28L0cbpHNHd-XoCTJD_MOgr4tvYJ1qidkstt_GjHFW_nBXtCouBH" +
        "GMGU0jFQu0PA73Zk9STK3cqdYRVwGz5vWW6nDvxeXfYVauIeRpBdojti2jI8OPu2bEh0OowOcWcVfGHWHs-8VEb_bo2yJgMnBoVd" +
        "mJSDT38NGRNIXDDHkBXE8b3KxsEBthpPyEGcTCSt2fA9PVnN7L1SdU8zDczFAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYD" +
        "VR0PAQH_BAQDAgEGMB0GA1UdDgQWBBRvahwWKOXPS0QtatVIWNTzUIMRwjAfBgNVHSMEGDAWgBTp-GUQC7TedX1XGVhfwNtQpyTm" +
        "NjANBgkqhkiG9w0BAQsFAAOCAQEAbxeDZiAJvuDhhl51pyCaZR9PmtHFmjJd8OxmxHqgKerWcU7xrIIfJMJPGRWcyJnJNc9RgpSj" +
        "wAZNH5oUu-yGkmuMqhpNtrwYo2fzkY7GjKOmlYBl0joq6Zik0uEOMlIG-Qt_16bfNv98gIGnZcpPfeDSYo1akIv8_3Pqd7f2mXx-" +
        "gn0ElA4YSv2Veca76_p4u8A4uvBTMgQtOg7ICxiGSQUwIvIrlFvDJp1WJNi85U2g7MTQC8T12dgw2YfO4um6tJS2oBMZkYLkJzIZ" +
        "B0X37cJTd6yrcwTvR5bOItR81ekLvyQITLJl-YMG8-9g9GfV2y6Xu7suCjgz1HV2h8fzWQ\"," +
        "  \"MIIDZjCCAk6gAwIBAgIBATANBgkqhkiG9w0BAQsFADBEMRMwEQYKCZImiZPyLGQBGRYDb3JnMRYwFAYKCZImiZPyLGQBGRYG" +
        "d2VicGtpMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwHhcNMDIwNzEwMTAwMDAwWhcNMzAwNzEwMDk1OTU5WjBEMRMwEQYKCZImiZPy" +
        "LGQBGRYDb3JnMRYwFAYKCZImiZPyLGQBGRYGd2VicGtpMRUwEwYDVQQDEwxEZW1vIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUA" +
        "A4IBDwAwggEKAoIBAQCcIMdTC698CeAYOWiB5tNCM2IudcpFueAQDQ4vV-bNj2oWaQ8Wl2IWO6UH2MAjYUqeZIgG2sPGuKiV27np" +
        "6VBPrp3ACYUcvwS8h2GlUSRbaMnIWIe_kVcytJzSsxopyrnwDdIN6iE4i-i2MX_i4riS97vALl1A5XfYk6mz4kaiXsYMpn-UFlRf" +
        "TsbQEFkKT5WArdVa0UvERnIS667ho3E2T35XzJ6vsGVUCXd-SwPWAneLNWjez50as0xwGdRKSO4YVuhJ14MWkk6bOXmGqloznDj3" +
        "N45dgyUhkqaPiKRzILQpPKW9UpceR2BmWQjstbJQcKRvVwXEed24goAYyc4lAgMBAAGjYzBhMA8GA1UdEwEB_wQFMAMBAf8wDgYD" +
        "VR0PAQH_BAQDAgEGMB0GA1UdDgQWBBTp-GUQC7TedX1XGVhfwNtQpyTmNjAfBgNVHSMEGDAWgBTp-GUQC7TedX1XGVhfwNtQpyTm" +
        "NjANBgkqhkiG9w0BAQsFAAOCAQEARI071BaQ1ljke73OsC-FoT0xbH1QZJdF5YX-Bjw7Peoz7C9_tBhR63CIajLTKOKVIAcufasX" +
        "hJdeMQ5sxbsFWtTCJlcm_z_eUOqmDPniskJI4bF8OanPEtuVeG4XEd2F_bpdDu9TYD_YqgfCNerFih1-Dm0gSJ4P63blts1-2J7V" +
        "JxoDuYXHjKfMlJGBqztagKJfTPRn7tpovKfdh_2GYFbDur1_fA_D2uH7Iis6ImG3Ehofi12v55PDhveEvI_LkgZuGgHdAT1x0BEJ" +
        "WYHt25kQ_DqDbz4qgjXV96jYyipRd6CdCYrUmsS4se00TwSOR4xDHEICjmXH_kh22Mfp7A\"" +
        "]");

    static KeyPair parseJwk(String jwk) {
        try {
            return JSONParser.parse(jwk).getKeyPair();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
    
    static final KeyPair RSA_KEY_1 = parseJwk(
        "{" +
        "  \"kty\": \"RSA\"," +
        "  \"n\": \"hCaR1AEH5I6zwp_vmyjrac1ENgqBH9jxu1afOUyRRMv_S--jP0ldOvdg6gwtddalQL1gy9hRcPs95jRa5ecYd8c4v" +
        "ZY4iUif9486f17V51Jv8mbmWBxbte754YGI-RN7EBeq-flRzHsmg91Tzf7vzf_QwgO_eGX2YPhjySzZCboZN77HrmN29VYkpdIZD" +
        "p26bJM5YmFMSwfXU6mp6dtCGZfnQl3L5Col3JcbFQap7nfrGnJBvPqtgq2L44O0C4HQ3AMWwKkqE89tWJsSP25wRy_KW00Nt5lNB" +
        "cvb-J93SKCCse8NEbfYW6SW4H2locBuTE6c53mb6Cd_IWQpwdbzxw\"," +
        "  \"e\": \"AQAB\"," +
        "  \"d\": \"DyhRX6zCl_-aNL-dfwGBhwApS72Gs_1xNJip6KuUmfyACtiws8iZbfMD5bSB3ltBVxyhpp_oL3pRzj7BEk-gadSq-" +
        "GvrjiuLVZzTC9r30_GLr5UH5KFUD5kahjgSWudWHTFpxgRH0plpgIR5YU5VeR5Xdnlxk8C2Mscqwt9nAYtxYPZGL1zIny9uV7hy2" +
        "9o6AizC4CjIvb5n0vzek8ZS7yw_yTAQDddboycFSLvKrL2EtjHNwtlQR0jLxWJ_SC5Oi6od5NqvcphfK9_2LGML3WmmsXWpS5Yko" +
        "yAohuSRDa1XvtkAr2vi7stXWSYC2sYnMvSAad5KJ55HKFxa1fe8SQ\"," +
        "  \"p\": \"0QW0PfzAlHju0uv063SHe9b9I__Jz7DkBando3hVC1PNatsk3BI19O93C1pFN8Rh0RGdl3Aqv6GhEdps_M0GeNQMI" +
        "byfxOI9QjUzRaLez5GX-fBsn4m4cT0TTPxXdmpTjE_caou1LCJp0CxnS7uFcCef5ow_1ESPW1h4e6w4Sps\"," +
        "  \"q\": \"odn72ss_X4qI-5fH6EmTRPBr_QmmEO7DsXeBqU_hUvRFds2ZrpscBT-5GEk1u9gBJEuQLgqAm65nm-pK-CHJV3y4e" +
        "qcuED-BjpuefeVdlzniMGsANo6d7ju8SFE2zo8kAzc9Hme_xkDZTXsiGbX4_ix1HGA998wsqo6qy99iCEU\"," +
        "  \"dp\": \"jMKQnOXnMpU2D6iC6UUyL_2Zv3J0D3-KLx4zefCBJP2safdmHSXOXEIfIvAJiQKg9NAuFludDivkckdr-dqAL0Jt" +
        "YRLLbSUGJ933xz9lWNctR03XeKCgKvH8W23b4Iy98tGdF8s5mJ0cMOqWLXP86ohksDdmjKYW_GbZzD8wMV0\"," +
        "  \"dq\": \"ahy3QYgVgXcbPhAR0VpDgmQ5-IjV5q4TgQt_59hmOvPJgw1i35Xz9gEEQkblQsVoYjpkSbs6_FaIuTEPe8Ty8zfi" +
        "3w8yZRatwyiF7bZt-NLLV8EfP6WbJ3DkjWkpjJ1OGAmkOYX9tmYX0fOTtNWYbFQLZ9I1bnvfIOcuVUGcTR0\"," +
        "  \"qi\": \"CnLmyI3yFO7QfO3vnfEYXyDaaIDg1JCmNL3-U1kxquRSDnYrRA_0Pcg-pN29ucI21pR2law7rUPAKCEdgeAoMpgs" +
        "dgYWB4XU1DLMo8KqMKMBZT36WYxGxQ5dvKLBy5YvMMEOVcfgdfjYnpQKF5FqqPMI5k3oMtC3K-QbLAZu2_I\"" +
        "}");
    
    static final KeyPair RSA_KEY_2 = parseJwk(
        "{" +
        "  \"kty\": \"RSA\"," +
        "  \"n\": \"kq1jB-6Gz0ahRxpSy9LWNf-zL9Cu5QNshEmXhJ6IVL33eFYMaggE3Gf_aoOGGtMAaj_ZbVJoT3-TO2rrTuOV0SzI7" +
        "WFHkiOcUZRgkxzU4cFklq1VyQHlTcdbX6-NV0znTdvC9HG6RzR3fl6AkyQ_zDoK-Lb2CdaonZLLbfxoxxVv5wV7QqLgRxjBlNIxU" +
        "LtDwO92ZPUkyt3KnWEVcBs-b1lupw78Xl32FWriHkaQXaI7YtoyPDj7tmxIdDqMDnFnFXxh1h7PvFRG_26NsiYDJwaFXZiUg09_D" +
        "RkTSFwwx5AVxPG9ysbBAbYaT8hBnEwkrdnwPT1Zzey9UnVPMw3MxQ\"," +
        "  \"e\": \"AQAB\"," +
        "  \"d\": \"C9t8b_22ZDc_fnIAU33d10uufqUOHnFiamdQmmX-e2tIADBknIW9btvxZ_jt9GkuVWiH-TB6QkL78ge4sg3v5JMMQ" +
        "zRkBspeLrIiBIKGKyHpMc0dbDx8_waoulmEwZPz9vVXE0_GUU9Kgaq-FicOCUJ_9I9F4JG729EsJN4M0lsn9gJn1FXuPFec0jeUu" +
        "E5SzpmBfsxALTFNogLlokOSNCOSk5675CPBn-9-kvmWZcT6dw7dsPtZLzZq7SKMYVyBfTzJC7Non0UGLolkl_YniTGvkScWRvAzO" +
        "VE7hEWsZe7OjokX5WoEReim9kXrnaovqt_TrzXiE9_L64r-Iz592Q\"," +
        "  \"p\": \"wvsVm10oOCm1n1HGHarwMWx2AFHDmKdS5cRnkjLtcJOvN9_RhWgyT4rwap6lEEZ6xMZzBhkKGJpFb-7NhMuf4NSiK" +
        "aqoH3DDMd24WKlII8RMMDei7uJKoDAJOLhuN3I8H1a8tIVU2H7YAgwpMueUN-FF4jDuoPs1slgwq6HbrY8\"," +
        "  \"q\": \"wJR1uqdym6KQmF1QWyq4RQWBF1pVQdlx0wCSUWnEu8zjxuhrx2uzuzyhAGpD-6C0EERlZYyRQkYEJS2zsiAU8C718" +
        "QTh2NnvVVJwYNgG-A92KhpUxL70VlWM3a274cWpj-1OVckreP3xSLubGb4y4jbPdi0W5fdASC7L2qQCnms\"," +
        "  \"dp\": \"J8V_isldwtb_LRhJCRQtGme9SiNjemfnCOcfGTs6I5R8UTFeU5AFcyQsFhN2J_O4Zxrzq3LAFHSjZUmYslW2ru2w" +
        "hj9BO-iMaEeJqswc4u7Pe6Zdncya3EHwH5m_IaAzk1Dl_QyVWfPFq-U_IhsKqLtSveitRDj5ov9KLjg9zxE\"," +
        "  \"dq\": \"axfkJGmL_Wq42FJEJn6qPI_kCvWMJfNjLgDKXYXhBsLZBDsp_JszNvNvYUi3B46Fs-olLQSvnthK49X3cR4QJsUm" +
        "teKOKcaAJsWSgvh_X6FRh_Zen47FV-F5VamQquv98HD6OBCIIV-ut1DE3tr7dvseAczvR_FoiPulF7BPWIM\"," +
        "  \"qi\": \"ssmk1NqS9OCm4HHlNdd-m2iafXUHIITaSSey-Z8ITei6o48iMx-YMmE9_5P2oBrlYitwol3vYtpt3f6WdjR2oCSC" +
        "dLAabfFaGdzoz5wJZg-86l5hHgKTXSjutVrTAIGboJ_jM1tPojY9FKopj1o0V4jaeOVtsh89ORiVDQC8LF4\"" +
        "}");
   
    static final KeyPair ECDSA_KEY = parseJwk(
        "{" +
        "  \"kty\": \"EC\"," +
        "  \"crv\": \"P-256\"," +
        "  \"x\": \"lNxNvAUEE8t7DSQBft93LVSXxKCiVjhbWWfyg023FCk\"," +
        "  \"y\": \"LmTlQxXB3LgZrNLmhOfMaCnDizczC_RfQ6Kx8iNwfFA\"," +
        "  \"d\": \"WdwYWh7yTRLOBXPMyc9v6u1OIQzjOmNmNFWOam3uqXY\"" +
        "}");
            
    static class SoftHSM {
        ////////////////////////////////////////////////////////////////////////////////////////
        // Private and secret keys would in a HSM implementation be represented as handles
        ////////////////////////////////////////////////////////////////////////////////////////
        private static LinkedHashMap<PublicKey, PrivateKey> key_management_keys = new LinkedHashMap<>();

        static private void addKMK(KeyPair keyPair) throws IOException, GeneralSecurityException {
            key_management_keys.put(keyPair.getPublic(), keyPair.getPrivate());
        }

        static {
            try {
                addKMK(RSA_KEY_1);
                addKMK(RSA_KEY_2);
                addKMK(ECDSA_KEY);
                KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
                kpg.initialize(512);
                KeyPair key_pair = kpg.generateKeyPair();
                addKMK(key_pair);  // INVALID
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }

        ECPrivateKey server_ec_private_key;

        byte[] session_key;

        public ECPublicKey generateEphemeralKey(KeyAlgorithms ec_key_algorithm) {
            try {
                KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
                ECGenParameterSpec eccgen = new ECGenParameterSpec(ec_key_algorithm.getJceName());
                generator.initialize(eccgen, new SecureRandom());
                KeyPair kp = generator.generateKeyPair();
                server_ec_private_key = (ECPrivateKey) kp.getPrivate();
                return (ECPublicKey) kp.getPublic();
            } catch (Exception e) {
                throw new SKSException(e);
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
                Mac mac = Mac.getInstance(HmacAlgorithms.HMAC_SHA256.getJceName());
                mac.init(new SecretKeySpec(Z, "RAW"));
                session_key = mac.doFinal(kdf_data);

                if (device_certificate == null) {
                    // The session key signature
                    mac = Mac.getInstance(HmacAlgorithms.HMAC_SHA256.getJceName());
                    mac.init(new SecretKeySpec(session_key, "RAW"));
                    byte[] session_key_attest = mac.doFinal(attestation_arguments);
                    if (!ArrayUtil.compare(session_key_attest, session_attestation)) {
                        throw new IOException("Verify attestation failed");
                    }
                } else {
                    PublicKey device_public_key = device_certificate.getPublicKey();
                    AsymSignatureAlgorithms signatureAlgorithm = device_public_key instanceof RSAKey ?
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
                Mac mac = Mac.getInstance(HmacAlgorithms.HMAC_SHA256.getJceName());
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
                SignatureWrapper km_sign = new SignatureWrapper(keyManagementKey instanceof RSAKey ?
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

    String session_key_algorithm = SecureKeyStore.ALGORITHM_SESSION_ATTEST_1;

    static final String ISSUER_URI = "http://issuer.example.com/provsess";

    GregorianCalendar clientTime;

    int provisioning_handle;

    short sessionLifeTime = 10000;

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
    ProvSess(Device device, 
             KeyAlgorithms sessionKeyAlgortihm, 
             short sessionKeyLimit, 
             Integer kmk_id, 
             boolean privacy_enabled, 
             String serv_sess) throws GeneralSecurityException, IOException {
        this.device = device;
        this.kmk_id = kmk_id;
        this.privacy_enabled = privacy_enabled;
        PublicKey keyManagementKey = kmk_id == null ? null : server_sess_key.enumerateKeyManagementKeys()[kmk_id];
        sks = device.sks;
        serverSessionId = serv_sess == null ? "S-" + Long.toHexString(new GregorianCalendar().getTimeInMillis()) + Long.toHexString(new SecureRandom().nextLong()) : serv_sess;
        String sess_key_alg = override_session_key_algorithm == null ? session_key_algorithm : override_session_key_algorithm;
        clientTime = new GregorianCalendar();
        String sessionKeyAlgorithmId = sessionKeyAlgortihm.getAlgorithmId(AlgorithmPreferences.SKS);
        if (sessionKeyAlgortihm.isMandatorySksAlgorithm() ||  device.device_info.supportedAlgorithms.contains(sessionKeyAlgorithmId)) {
            server_ephemeral_key = server_sess_key.generateEphemeralKey(sessionKeyAlgortihm);
        } else if ((server_ephemeral_key = nonSKSTypes.get(sessionKeyAlgortihm)) == null) {
            throw new IOException("Bug:" + sessionKeyAlgorithmId);
        }
        ProvisioningSession sess =
                device.sks.createProvisioningSession(sess_key_alg,
                        privacy_enabled,
                        serverSessionId,
                        server_ephemeral_key,
                        ISSUER_URI,
                        keyManagementKey,
                        (int) (clientTime.getTimeInMillis() / 1000),
                        sessionLifeTime,
                        sessionKeyLimit,
                        SKSTest.serverCertificate);
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
        attestation_arguments.addShort(sessionLifeTime);
        attestation_arguments.addShort(sessionKeyLimit);
        attestation_arguments.addArray(SKSTest.serverCertificate);

        server_sess_key.generateAndVerifySessionKey(sess.getClientEphemeralKey(),
                kdf.getResult(),
                attestation_arguments.getResult(),
                privacy_enabled ? null : device.device_info.getCertificatePath()[0],
                sess.getAttestation());
    }

    public void byPassKMK(int kmk_id) {
        this.kmk_id = kmk_id;
    }

    ProvSess(Device device, short sessionKeyLimit, Integer kmk_id, boolean privacy_enabled, String serv_sess) 
            throws GeneralSecurityException, IOException {
        this(device, KeyAlgorithms.NIST_P_256, sessionKeyLimit, kmk_id, privacy_enabled, serv_sess);
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

    public ProvSess(Device device, KeyAlgorithms sessionKeyAlgortihm) throws GeneralSecurityException, IOException {
        this(device, sessionKeyAlgortihm, (short) 50, null, false, null);
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
                            KeyAlgorithms keyAlgorithm,
                            KeyProtectionSpec keyProtectionSpec,
                            AppUsage appUsage) throws SKSException, IOException, GeneralSecurityException {
        return createKey(id, 
                         keyAlgorithm, 
                         keyProtectionSpec,
                         appUsage, 
                         null);
    }

    public GenKey createKey(String id,
                            KeyAlgorithms keyAlgorithm,
                            KeyProtectionSpec keyProtectionSpec,
                            AppUsage appUsage,
                            String[] endorsedAlgorithms) throws SKSException, IOException, GeneralSecurityException {
        byte[] serverSeed = new byte[32];
        new SecureRandom().nextBytes(serverSeed);
        return createKey(id,
                SecureKeyStore.ALGORITHM_KEY_ATTEST_1,
                serverSeed,
                keyProtectionSpec.pinPolicy,
                keyProtectionSpec.pin,
                keyProtectionSpec.biometricProtection /* biometricProtection */,
                ExportProtection.NON_EXPORTABLE /* export_policy */,
                DeleteProtection.NONE /* delete_policy */,
                false /* enablePinCaching */,
                appUsage,
                "" /* friendlyName */,
                new KeySpecifier(keyAlgorithm),
                endorsedAlgorithms);
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
        byte[] keyMac;
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
                keyMac = mac4call(key_entry_mac.getResult(), SecureKeyStore.METHOD_CREATE_KEY_ENTRY));
        MacGenerator key_attestation = new MacGenerator();
        key_attestation.addArray(key_entry.getPublicKey().getEncoded());
        key_attestation.addArray(keyMac);
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
        if (key.publicKey instanceof RSAKey && !((RSAPublicKey) key.publicKey).getPublicExponent().equals(exponent)) {
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

}

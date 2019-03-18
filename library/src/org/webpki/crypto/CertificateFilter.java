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
package org.webpki.crypto;

import java.io.IOException;

import java.math.BigInteger;

import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.Vector;

import java.util.regex.Pattern;

import java.security.cert.X509Certificate;

import java.security.GeneralSecurityException;
import java.security.MessageDigest;

import javax.security.auth.x500.X500Principal;

import org.webpki.util.ArrayUtil;

public class CertificateFilter {

    public static final String CF_FINGER_PRINT        = "fingerPrint";
    public static final String CF_ISSUER_REG_EX       = "issuerRegEx";
    public static final String CF_SERIAL_NUMBER       = "serialNumber";
    public static final String CF_SUBJECT_REG_EX      = "subjectRegEx";
    public static final String CF_EMAIL_REG_EX        = "emailRegEx";
    public static final String CF_POLICY_RULES        = "policyRules";
    public static final String CF_KEY_USAGE_RULES     = "keyUsageRules";
    public static final String CF_EXT_KEY_USAGE_RULES = "extendedKeyUsageRules";

    // Global - Needs path expansion

    byte[] fingerPrint;

    String issuerRegEx;

    // Local

    String subjectRegEx;

    String emailRegEx;

    String[] policyRules;

    BigInteger serialNumber;

    String[] keyUsageRules;

    String[] extendedKeyUsageRules;

    static final Pattern oidPattern = Pattern.compile("[1-9][0-9]*(\\.[1-9][0-9]*)*");

    static final char DISALLOWED = '-';

    static abstract class BaseRuleParser {

        LinkedHashMap<String, Boolean> rules = new LinkedHashMap<String, Boolean>();

        BaseRuleParser(String[] ruleSet) throws IOException {
            if (ruleSet != null) {
                if (ruleSet.length == 0) {
                    throw new IOException("Empty list not allowed");
                }
                for (String rule : ruleSet) {
                    boolean required = true;
                    if (rule.charAt(0) == DISALLOWED) {
                        required = false;
                        rule = rule.substring(1);
                    }
                    if (rules.put(parse(rule), required) != null) {
                        throw new IOException("Duplicate rule: " + rule);
                    }
                }
            }
        }

        String[] normalized() {
            if (rules.isEmpty()) {
                return null;
            }
            LinkedHashSet<String> ruleSet = new LinkedHashSet<String>();
            for (String rule : rules.keySet()) {
                ruleSet.add(rules.get(rule) ? rule : DISALLOWED + rule);
            }
            return ruleSet.toArray(new String[0]);
        }

        abstract String parse(String argument) throws IOException;

        boolean checkRule(String rule) {
            Boolean required = rules.get(rule);
            if (required != null) {
                if (required) {
                    rules.remove(rule);
                }
                return required;
            }
            return true;
        }

        boolean gotAllRequired() {
            for (String rule : rules.keySet()) {
                if (rules.get(rule)) {
                    return false;
                }
            }
            return true;
        }
    }

    static class KeyUsageRuleParser extends BaseRuleParser {
        KeyUsageRuleParser(String[] ruleSet) throws IOException {
            super(ruleSet);
        }

        @Override
        String parse(String argument) throws IOException {
            return KeyUsageBits.getKeyUsageBit(argument).getX509Name();
        }
    }

    static class OIDRuleParser extends BaseRuleParser {
        OIDRuleParser(String[] ruleSet) throws IOException {
            super(ruleSet);
        }

        @Override
        String parse(String argument) throws IOException {
            if (!oidPattern.matcher(argument).matches()) {
                throw new IOException("Bad OID: " + argument);
            }
            return argument;
        }
    }


    private String quote(X500Principal principal) {
        return Pattern.quote(principal.getName());
    }


    private String conditionalCompile(String regex) {
        if (regex != null) {
            Pattern.compile(regex);
        }
        return regex;
    }

    protected void nullCheck(Object o) throws IOException {

    }


    public byte[] getFingerPrint() {
        return fingerPrint;
    }


    public String getIssuerRegEx() {
        return issuerRegEx;
    }


    public String getSubjectRegEx() {
        return subjectRegEx;
    }


    public String getEmailRegEx() {
        return emailRegEx;
    }


    public String[] getPolicyRules() {
        return policyRules;
    }


    public BigInteger getSerialNumber() {
        return serialNumber;
    }


    public String[] getKeyUsageRules() {
        return keyUsageRules;
    }


    public String[] getExtendedKeyUsageRules() {
        return extendedKeyUsageRules;
    }


    public CertificateFilter setFingerPrint(byte[] fingerPrint) throws IOException {
        nullCheck(fingerPrint);
        if (fingerPrint != null && fingerPrint.length != 32) {
            throw new IOException("\"Sha256\" fingerprint <> 32 bytes!");
        }
        this.fingerPrint = fingerPrint;
        return this;
    }


    public CertificateFilter setIssuer(X500Principal issuer) throws IOException {
        nullCheck(issuer);
        this.issuerRegEx = quote(issuer);
        return this;
    }


    public CertificateFilter setSubject(X500Principal subject) throws IOException {
        nullCheck(subject);
        this.subjectRegEx = quote(subject);
        return this;
    }


    public CertificateFilter setIssuerRegEx(String issuerRegEx) throws IOException {
        nullCheck(issuerRegEx);
        this.issuerRegEx = conditionalCompile(issuerRegEx);
        return this;
    }


    public CertificateFilter setSubjectRegEx(String subjectRegEx) throws IOException {
        nullCheck(subjectRegEx);
        this.subjectRegEx = conditionalCompile(subjectRegEx);
        return this;
    }


    public CertificateFilter setEmail(String emailAddress) throws IOException {
        nullCheck(emailAddress);
        this.emailRegEx = Pattern.quote(emailAddress);
        return this;
    }


    public CertificateFilter setEmailRegEx(String emailRegEx) throws IOException {
        nullCheck(emailRegEx);
        this.emailRegEx = conditionalCompile(emailRegEx);
        return this;
    }


    public CertificateFilter setPolicyRules(String[] ruleSet) throws IOException {
        nullCheck(ruleSet);
        this.policyRules = new OIDRuleParser(ruleSet).normalized();
        return this;
    }

    public CertificateFilter setSerialNumber(BigInteger serialNumber) throws IOException {
        nullCheck(serialNumber);
        this.serialNumber = serialNumber;
        return this;
    }

    public CertificateFilter setKeyUsageRules(String[] keyUsageRules) throws IOException {
        nullCheck(keyUsageRules);
        this.keyUsageRules = new KeyUsageRuleParser(keyUsageRules).normalized();
        return this;
    }

    public CertificateFilter setKeyUsageRules(KeyUsageBits[] required, KeyUsageBits[] disallowed) throws IOException {
        nullCheck(required);
        nullCheck(disallowed);
        Vector<String> list = new Vector<String>();
        for (KeyUsageBits kub : required) {
            list.add(kub.getX509Name());
        }
        for (KeyUsageBits kub : disallowed) {
            list.add(DISALLOWED + kub.getX509Name());
        }
        this.keyUsageRules = new KeyUsageRuleParser(list.toArray(new String[0])).normalized();
        return this;
    }

    /*
     * The argument
     *   new String[]{"1.3.6.1.5.5.7.3.2","1.3.6.1.5.5.7.3.4"}
     *   requires matching end-entity certificates to have (at least) the two extended key usages,
     *   clientAuthentication and emailProtection
     */
    public CertificateFilter setExtendedKeyUsageRules(String[] extendedKeyUsageRules) throws IOException {
        nullCheck(extendedKeyUsageRules);
        this.extendedKeyUsageRules = new OIDRuleParser(extendedKeyUsageRules).normalized();
        return this;
    }

    public boolean needsPathExpansion() {
        return fingerPrint != null || issuerRegEx != null;
    }


    public static boolean matchKeyUsage(String[] specifier, X509Certificate certificate) throws IOException {
        if (specifier == null) {
            return true;
        }
        boolean[] keyUsage = certificate.getKeyUsage();
        if (keyUsage == null) {
            return false;
        }
        KeyUsageRuleParser rule_parser = new KeyUsageRuleParser(specifier);
        for (KeyUsageBits kub : KeyUsageBits.values()) {
            if (kub.ordinal() < keyUsage.length) {
                if (keyUsage[kub.ordinal()]) {
                    if (!rule_parser.checkRule(kub.getX509Name())) {
                        return false;
                    }
                }
            }
        }
        return rule_parser.gotAllRequired();
    }


    private static boolean matchExtendedKeyUsage(String[] specifier, X509Certificate certificate) throws IOException {
        if (specifier == null) {
            return true;
        }
        String[] ekus = CertificateUtil.getExtendedKeyUsage(certificate);
        if (ekus == null) {
            return false;
        }
        OIDRuleParser rule_parser = new OIDRuleParser(specifier);
        for (String eku : ekus) {
            if (!rule_parser.checkRule(eku)) {
                return false;
            }
        }
        return rule_parser.gotAllRequired();
    }


    private static boolean matchEmailAddress(String specifier, X509Certificate certificate) throws IOException {
        if (specifier == null) {
            return true;
        }
        String[] emailAddresses = CertificateUtil.getSubjectEmailAddresses(certificate);
        if (emailAddresses == null) {
            return false;
        }
        Pattern regex = Pattern.compile(specifier);
        for (String emailAddress : emailAddresses) {
            if (regex.matcher(emailAddress).matches()) {
                return true;
            }
        }
        return false;
    }


    private static boolean matchPolicy(String specifier[], X509Certificate certificate) throws IOException {
        if (specifier == null) {
            return true;
        }
        String[] policies = CertificateUtil.getPolicyOIDs(certificate);
        if (policies == null) {
            return false;
        }
        OIDRuleParser ruleParser = new OIDRuleParser(specifier);
        for (String policy : policies) {
            if (!ruleParser.checkRule(policy)) {
                return false;
            }
        }
        return ruleParser.gotAllRequired();
    }


    private static boolean matchDistinguishedName(String specifier, X509Certificate[] certificatePath, boolean issuer) {
        if (specifier == null) {
            return true;
        }
        Pattern pattern = Pattern.compile(specifier);
        int pathLen = issuer ? certificatePath.length : 1;
        for (int q = 0; q < pathLen; q++) {
            String dn = issuer ? certificatePath[q].getIssuerX500Principal().getName(X500Principal.RFC2253)
                    :
                    certificatePath[q].getSubjectX500Principal().getName(X500Principal.RFC2253);
            if (pattern.matcher(dn).matches()) {
                return true;
            }
        }
        return false;
    }


    private static boolean matchFingerPrint(byte[] specifier, X509Certificate[] certificatePath) throws GeneralSecurityException {
        if (specifier == null) {
            return true;
        }
        for (X509Certificate certificate : certificatePath) {
            if (ArrayUtil.compare(specifier, MessageDigest.getInstance("SHA256").digest(certificate.getEncoded()))) {
                return true;
            }
        }
        return false;
    }


    private static boolean matchSerial(BigInteger specifier, X509Certificate certificate) {
        if (specifier == null) {
            return true;
        }
        return specifier.equals(certificate.getSerialNumber());
    }


    public boolean matches(X509Certificate[] certificatePath) throws IOException {
        try {
            return matchSerial(serialNumber, certificatePath[0]) &&
                   matchFingerPrint(fingerPrint, certificatePath) &&
                   matchKeyUsage(keyUsageRules, certificatePath[0]) &&
                   matchExtendedKeyUsage(extendedKeyUsageRules, certificatePath[0]) &&
                   matchPolicy(policyRules, certificatePath[0]) &&
                   matchEmailAddress(emailRegEx, certificatePath[0]) &&
                   matchDistinguishedName(issuerRegEx, certificatePath, true) &&
                   matchDistinguishedName(subjectRegEx, certificatePath, false);
        } catch (GeneralSecurityException e) {
            throw new IOException(e);
        }
    }
}

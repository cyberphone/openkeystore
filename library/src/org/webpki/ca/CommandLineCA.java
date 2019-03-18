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
package org.webpki.ca;

import java.io.IOException;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.math.BigInteger;

import java.util.Vector;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.TimeZone;

import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.GeneralSecurityException;

import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.ECGenParameterSpec;

import java.security.cert.Certificate;
import java.security.cert.X509Certificate;

import org.webpki.asn1.cert.DistinguishedName;

import org.webpki.crypto.AsymSignatureAlgorithms;
import org.webpki.crypto.ExtendedKeyUsages;
import org.webpki.crypto.KeyAlgorithms;
import org.webpki.crypto.AsymKeySignerInterface;
import org.webpki.crypto.KeyUsageBits;
import org.webpki.crypto.CustomCryptoProvider;
import org.webpki.crypto.SignatureWrapper;


public class CommandLineCA {
    Vector<CmdLineArgument> list = new Vector<CmdLineArgument>();

    int max_display;

    String helptext;

    private void bad(String what) throws IOException {
        throw new IOException(what);
    }


    class CmdLineArgument {
        CmdLineArgumentGroup group;
        CmdLineArgumentGroup mutually_exclusive_group;
        String helptext;
        String command;
        String optargument;
        String defaultvalue;
        Vector<String> argvalue = new Vector<String>();
        CmdFrequency frequency;
        boolean found;

        String temparg;

        CmdLineArgument(CmdLineArgumentGroup group,
                        String command,
                        String optargument,
                        String helptext,
                        CmdFrequency frequency,
                        String defaultvalue) {
            this.group = group;
            this.command = command;
            this.optargument = optargument;
            this.helptext = helptext;
            this.frequency = frequency;
            this.defaultvalue = defaultvalue;
            int i = command.length() + 1;
            if (optargument != null) {
                i += optargument.length() + 3;
            }
            if (i > max_display) {
                max_display = i;
            }
            for (CmdLineArgument c : list) {
                if (c.command.equals(command)) {
                    System.out.println("\n****Duplicate command line init: " + command);
                    System.exit(3);
                }
            }
            list.add(this);
        }

        int getInteger() throws IOException {
            return Integer.parseInt(getString());
        }

        String getString() throws IOException {
            if (argvalue.size() != 1) {
                bad("Internal argument error for command: " + command);
            }
            return argvalue.elementAt(0).trim();
        }

        AsymSignatureAlgorithms getAlgorithm() throws IOException {
            return AsymSignatureAlgorithms.valueOf(getString());
        }

        KeyAlgorithms getECCDomain() throws IOException {
            return KeyAlgorithms.valueOf(getString());
        }

        BigInteger getBigInteger() throws IOException {
            return new BigInteger(getString());
        }

        int get1Dec() throws IOException {
            try {
                int v = Integer.parseInt(temparg.substring(0, 1));
                temparg = temparg.substring(1);
                return v;
            } catch (NumberFormatException nfe) {
                bad("DateTime digit expected: " + temparg);
                return 0;  // For the parser only
            }
        }

        int get2Dec() throws IOException {
            return get1Dec() * 10 + get1Dec();
        }

        int eatDelimAndGet2Dec(char delim) throws IOException {
            if (temparg.toUpperCase().charAt(0) != delim) {
                bad("DateTime delimiter expected: " + delim);
            }
            temparg = temparg.substring(1);
            return get1Dec() * 10 + get1Dec();
        }

        /**
         * dateTime       = YYYY "-" MM "-" DD "T" hh ":" mm ":" ss
         */
        Date getDateTime() throws IOException {
            GregorianCalendar gc = new GregorianCalendar();
            gc.clear();

            temparg = getString();

            if (temparg.length() != 19) {
                bad("Malformed dateTime (" + temparg + ").");
            }

            gc.set(GregorianCalendar.ERA, GregorianCalendar.AD);
            gc.set(GregorianCalendar.YEAR, get2Dec() * 100 + get2Dec());

            gc.set(GregorianCalendar.MONTH, eatDelimAndGet2Dec('-') - 1);

            gc.set(GregorianCalendar.DAY_OF_MONTH, eatDelimAndGet2Dec('-'));

            gc.set(GregorianCalendar.HOUR_OF_DAY, eatDelimAndGet2Dec('T'));

            gc.set(GregorianCalendar.MINUTE, eatDelimAndGet2Dec(':'));

            gc.set(GregorianCalendar.SECOND, eatDelimAndGet2Dec(':'));

            gc.setTimeZone(TimeZone.getTimeZone("UTC"));

            return gc.getTime();
        }

        char[] toCharArray() throws IOException {
            return getString().toCharArray();
        }

    }

    enum CmdLineArgumentGroup {
        GENERAL,
        KEYSTORE_SIGNED,
        SELF_SIGNED,
        EE_ENTITY,
        CA_ENTITY
    }

    enum CmdFrequency {
        OPTIONAL,
        SINGLE,
        OPTIONAL_MULTIPLE,
        MULTIPLE
    }

    CmdLineArgument create(CmdLineArgumentGroup group, String command, String optargument, String helptext, CmdFrequency frequency) {
        return new CmdLineArgument(group, command, optargument, helptext, frequency, null);
    }

    CmdLineArgument create(CmdLineArgumentGroup group, String command, String optargument, String helptext, String defaultvalue) {
        return new CmdLineArgument(group, command, optargument, helptext, CmdFrequency.OPTIONAL, defaultvalue);
    }


    class CertificateSigner implements AsymKeySignerInterface {
        PrivateKey sign_key;
        PublicKey publicKey;

        CertificateSigner(PrivateKey sign_key, PublicKey publicKey) {
            this.sign_key = sign_key;
            this.publicKey = publicKey;
        }


        public byte[] signData(byte[] data, AsymSignatureAlgorithms certalg) throws IOException {
            try {
                return new SignatureWrapper(certalg, sign_key)
                        .setEcdsaSignatureEncoding(true)
                        .update(data)
                        .sign();
            } catch (GeneralSecurityException e) {
                throw new IOException(e);
            }
        }


        public PublicKey getPublicKey() throws IOException {
            return publicKey;
        }

    }


    void setMutuallyExclusive(CmdLineArgumentGroup group1, CmdLineArgumentGroup group2) {
        for (CmdLineArgument cla1 : list) {
            if (cla1.group == group1) {
                for (CmdLineArgument cla2 : list) {
                    if (cla2.group == group2) {
                        cla1.mutually_exclusive_group = group2;
                        cla2.mutually_exclusive_group = group1;
                    }
                }
            }
        }
    }

    void checkConsistency() throws IOException {
        for (CmdLineArgument cla1 : list) {
            if (cla1.found) {
                // Now check for mutual exclusion....
                for (CmdLineArgument cla2 : list) {
                    if (cla1.group == cla2.mutually_exclusive_group && cla2.found) {
                        bad("Command '-" + cla1.command + "' cannot be combined with '-" + cla2.command + "'");
                    }
                }
            } else if (cla1.frequency == CmdFrequency.SINGLE || cla1.frequency == CmdFrequency.MULTIPLE) {
                String other = "";
                boolean bad = true;
                for (CmdLineArgument cla2 : list) {
                    if (cla1.group == cla2.mutually_exclusive_group) {
                        if (cla2.found) {
                            bad = false;
                            break;
                        }
                        if (cla2.frequency == CmdFrequency.SINGLE || cla2.frequency == CmdFrequency.MULTIPLE) {
                            other = " or -" + cla2.command;
                            for (CmdLineArgument cla3 : list) {
                                if (cla3.found && cla3.group == cla1.group) {
                                    other = "";
                                    break;
                                }
                            }
                        }
                    }
                }
                if (bad) {
                    bad("Missing command: -" + cla1.command + other);
                }
            } else if (cla1.frequency == CmdFrequency.OPTIONAL && cla1.defaultvalue != null) {
                boolean do_it = true;
                for (CmdLineArgument cla2 : list) {
                    if (cla1.group == cla2.mutually_exclusive_group) {
                        if (cla2.found) {
                            do_it = false;
                            break;
                        }
                    }
                }
                if (do_it) {
                    cla1.argvalue.add(cla1.defaultvalue);
                    cla1.found = true;
                }
            }
        }
    }


    void printHelpLine() {
        if (helptext == null) return;
        int i = 0;
        for (int j = 0; j < helptext.length(); j++) {
            if (helptext.charAt(j) == ' ') {
                if (j < 68 - max_display) {
                    i = j;
                }
            }
        }
        if (i > 0 && helptext.length() >= 68 - max_display) {
            System.out.print(helptext.substring(0, i++));
            helptext = helptext.substring(i);
        } else {
            System.out.print(helptext);
            helptext = null;
        }
    }


    void show() {
        System.out.print("\nUsage: " + this.getClass().getName() + " options\n\n     OPTIONS\n\n");
        for (CmdLineArgument cla : list) {
            helptext = cla.helptext;
            if (cla.frequency == CmdFrequency.OPTIONAL || cla.frequency == CmdFrequency.OPTIONAL_MULTIPLE) {
                helptext = "OPTIONAL.  " + helptext;
                if (cla.frequency == CmdFrequency.OPTIONAL_MULTIPLE) {
                    helptext += ".  The command may be REPEATED";
                }
            }
            System.out.print("       -" + cla.command);
            int i = cla.command.length() - 3;
            if (cla.optargument != null) {
                i += cla.optargument.length() + 3;
                System.out.print(" \"" + cla.optargument + "\"");
            }
            while (i++ < max_display) {
                System.out.print(" ");
            }
            printHelpLine();
            System.out.println();
            if (cla.defaultvalue != null) {
                System.out.print("           default: " + cla.defaultvalue);
                i = cla.defaultvalue.length() + 9;
                while (i++ < max_display) {
                    System.out.print(" ");
                }
                printHelpLine();
                System.out.println();
            }
            while (helptext != null) {
                i = -11;
                while (i++ < max_display) {
                    System.out.print(" ");
                }
                printHelpLine();
                System.out.println();
            }
            System.out.println();
        }
    }


    String eccCurves() {
        StringBuilder s = new StringBuilder();
        boolean comma = false;
        for (KeyAlgorithms curve : KeyAlgorithms.values()) {
            if (curve.isECKey()) {
                if (comma) {
                    s.append(", ");
                }
                comma = true;
                s.append(curve.toString());
            }
        }
        return s.toString();
    }


    String sigAlgs() {
        StringBuilder s = new StringBuilder();
        boolean comma = false;
        for (AsymSignatureAlgorithms sigalg : AsymSignatureAlgorithms.values()) {
            if (comma) {
                s.append(", ");
            }
            comma = true;
            s.append(sigalg.toString());
        }
        return s.toString();
    }


    String keyUsages() {
        StringBuilder s = new StringBuilder();
        boolean comma = false;
        for (KeyUsageBits keybit : KeyUsageBits.values()) {
            if (comma) {
                s.append(", ");
            }
            comma = true;
            s.append(keybit.getX509Name());
        }
        return s.toString();
    }


    String ExtkeyUsages() {
        StringBuilder s = new StringBuilder();
        boolean comma = false;
        for (ExtendedKeyUsages eku : ExtendedKeyUsages.values()) {
            if (comma) {
                s.append(", ");
            }
            comma = true;
            s.append(eku.getX509Name());
        }
        return s.toString();
    }


    String getKeyUsage(boolean caflag) {
        CertSpec cert_spec = new CertSpec();
        if (caflag) {
            cert_spec.setCACertificateConstraint();
        } else {
            cert_spec.setEndEntityConstraint();
        }
        StringBuilder s = new StringBuilder(", and default KeyUsage [");
        boolean comma = false;
        for (KeyUsageBits kubit : cert_spec.key_usage_set) {
            if (comma) {
                s.append(", ");
            }
            comma = true;
            s.append(kubit.getX509Name());
        }
        return s.append("] extensions.  Note that any suitable KeyUsage can be set by issuing " +
                "\"-extension/ku\" commands, which clears the default settings").toString();
    }


    BigInteger createSerial() {
        return new BigInteger(String.valueOf(new Date().getTime()));
    }


    CmdLineArgument CMD_self_signed = create(CmdLineArgumentGroup.SELF_SIGNED,
            "selfsigned", null,
            "Create a self-signed certificate. The alternative is using the \"CA\" options below",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_ca_keystore = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/keystore", "file",
            "CA keystore file",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_ca_ks_type = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/storetype", "type",
            "CA keystore type",
            "JKS");

    CmdLineArgument CMD_ca_ks_pass = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/storepass", "password",
            "CA keystore password",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_ca_key_pass = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/keypass", "password",
            "CA signature key password",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_ca_key_alias = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/keyalias", "alias",
            "CA key alias",
            "mykey");

    CmdLineArgument CMD_ca_addpath = create(CmdLineArgumentGroup.KEYSTORE_SIGNED,
            "ca/addpath", "qualifier",
            "Add CA certificate(s) to generated key entry.  " +
                    "The qualifier must be \"all\" or a positive integer (1-n) " +
                    "indicating how many of the available CA certificates " +
                    "that should be added to the target certificate",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_serial = create(CmdLineArgumentGroup.GENERAL,
            "serial", "serial-number",
            "Set certificate serial number.  If not set, a unique " +
                    "serial number will be generated",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_subject_dn = create(CmdLineArgumentGroup.GENERAL,
            "subject", "distinguished-name",
            "Set subject distinguished name",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_valid_start = create(CmdLineArgumentGroup.GENERAL,
            "validity/start", "date-time",
            "Set certificate validity start in UTC. Syntax: YYYY '-' MM '-' DD 'T' hh ':' mm ':' ss.  Example: 2003-03-10T10:00:00",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_valid_end = create(CmdLineArgumentGroup.GENERAL,
            "validity/end", "date-time",
            "Set certificate validity end in UTC. Syntax: see validity/start",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_rsa_key_size = create(CmdLineArgumentGroup.GENERAL,
            "keysize", "key-size",
            "Set size of the generated public and private RSA keys",
            "1024");

    CmdLineArgument CMD_ecc_curve = create(CmdLineArgumentGroup.GENERAL,
            "ecccurve", "curve-name",
            "Set the curve-name for generated ECC keys, select from: " + eccCurves(),
            (String) null);

    CmdLineArgument CMD_exponent = create(CmdLineArgumentGroup.GENERAL,
            "exponent", "value",
            "Set the value of the RSA public key exponent",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_sig_alg = create(CmdLineArgumentGroup.GENERAL,
            "sigalg", "signature-algorithm",
            "Set signature algorithm for signing the certificate, select from: " + sigAlgs(),
            AsymSignatureAlgorithms.RSA_SHA1.toString());

    CmdLineArgument CMD_out_keystore = create(CmdLineArgumentGroup.GENERAL,
            "out/keystore", "file",
            "Set where to WRITE the resulting certificate(s) and private key",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_out_ks_type = create(CmdLineArgumentGroup.GENERAL,
            "out/storetype", "type",
            "Set target keystore type",
            "JKS");

    CmdLineArgument CMD_out_update = create(CmdLineArgumentGroup.GENERAL,
            "out/update", null,
            "Update an existing keystore (the default action is simply " +
                    "overwriting/creating the target keystore)" +
                    ".  Note that you can update an existing key alias",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_out_ks_pass = create(CmdLineArgumentGroup.GENERAL,
            "out/storepass", "password",
            "Set the password to the created/updated keystore",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_out_pkey_pass = create(CmdLineArgumentGroup.GENERAL,
            "out/keypass", "password",
            "Set the password to the generated private key",
            CmdFrequency.SINGLE);

    CmdLineArgument CMD_out_key_alias = create(CmdLineArgumentGroup.GENERAL,
            "out/keyalias", "alias",
            "Set key alias to the resulting certificate(s) and private key",
            "mykey");

    CmdLineArgument CMD_ca_cert = create(CmdLineArgumentGroup.CA_ENTITY,
            "entity/ca", null,
            "Set the CA certificate BasicConstraints, SKI, AKI" + getKeyUsage(true),
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_ee_cert = create(CmdLineArgumentGroup.EE_ENTITY,
            "entity/ee", null,
            "Set the end-entity certificate BasicConstraints, SKI, AKI" + getKeyUsage(false),
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_key_usage = create(CmdLineArgumentGroup.GENERAL,
            "extension/ku", "key-usage-bit",
            "Set a specific KeyUsage bit, select from: " + keyUsages(),
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_email = create(CmdLineArgumentGroup.GENERAL,
            "extension/email", "e-mail-address",
            "Add an e-mail address SubjectAltName (SAN) extension",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_eku = create(CmdLineArgumentGroup.GENERAL,
            "extension/eku", "extended-key-usage",
            "Add an ExtendedKeyUsage OID, select from: " + ExtkeyUsages(),
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_dns = create(CmdLineArgumentGroup.GENERAL,
            "extension/dns", "dns-name",
            "Add a DNS name SubjectAltName (SAN) extension",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_ip = create(CmdLineArgumentGroup.GENERAL,
            "extension/ip", "ip-address",
            "Add an IP address SubjectAltName (SAN) extension",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_ski = create(CmdLineArgumentGroup.GENERAL,
            "extension/ski", null,
            "Set the SubjectKeyIdentifier (SKI) extension",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_ext_aki = create(CmdLineArgumentGroup.GENERAL,
            "extension/aki", null,
            "Set the AuthorityKeyIdentifier (AKI) extension",
            CmdFrequency.OPTIONAL);

    CmdLineArgument CMD_ext_certpol = create(CmdLineArgumentGroup.GENERAL,
            "extension/policy", "oid",
            "Add a certificate policy OID",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_ocsp = create(CmdLineArgumentGroup.GENERAL,
            "extension/ocsp", "uri",
            "Add an AuthorityInfoAccess (AIA) OCSP responder URI",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_caissuers = create(CmdLineArgumentGroup.GENERAL,
            "extension/caissuer", "uri",
            "Add an AuthorityInfoAccess (AIA) CA issuer URI",
            CmdFrequency.OPTIONAL_MULTIPLE);

    CmdLineArgument CMD_ext_cdp = create(CmdLineArgumentGroup.GENERAL,
            "extension/cdp", "uri",
            "Add a CRL Distribution Point (CDP) URI",
            CmdFrequency.OPTIONAL_MULTIPLE);

    private CommandLineCA() {
        setMutuallyExclusive(CmdLineArgumentGroup.KEYSTORE_SIGNED, CmdLineArgumentGroup.SELF_SIGNED);
        setMutuallyExclusive(CmdLineArgumentGroup.CA_ENTITY, CmdLineArgumentGroup.EE_ENTITY);
    }


    CmdLineArgument get(String argument) throws IOException {
        for (CmdLineArgument cla : list) {
            if (cla.command.equals(argument.substring(1))) {
                if (cla.found && (cla.frequency == CmdFrequency.OPTIONAL || cla.frequency == CmdFrequency.SINGLE)) {
                    bad("Duplicate command: " + argument);
                }
                cla.found = true;
                return cla;
            }
        }
        bad("No such command: " + argument);
        return null;  // For the parser only
    }


    void decodeCommandLine(String argv[]) throws IOException {
        if (argv.length == 0) {
            show();
            System.exit(3);
        }
        for (int i = 0; i < argv.length; i++) {
            String arg = argv[i];
            if (arg.indexOf('-') != 0) {
                bad("Command '" + arg + "' MUST start with a '-'");
            }
            CmdLineArgument cla = get(arg);
            if (cla.optargument == null) continue;
            if (++i >= argv.length) {
                bad("Missing argument for command: " + arg);
            }
            String opt = argv[i];
            if (opt.indexOf('-') == 0) {
                bad("Argument to command '" + arg + "' MUST NOT start with a '-'");
            }
            cla.argvalue.add(opt);
        }
        checkConsistency();
    }


    void certify(String sun_pkcs12) throws IOException {
        try {
            CA ca = new CA();
            CertSpec certspec = new CertSpec();

            // Time to execute!

            ///////////////////////////////////////////////////////////////
            // Create the target certificate key-pair
            ///////////////////////////////////////////////////////////////
            KeyPairGenerator kpg = null;
            if (CMD_ecc_curve.found) {
                kpg = KeyPairGenerator.getInstance("EC");
                kpg.initialize(new ECGenParameterSpec(CMD_ecc_curve.getECCDomain().getJceName()));
            } else {
                kpg = KeyPairGenerator.getInstance("RSA");
                if (CMD_exponent.found) {
                    kpg.initialize(new RSAKeyGenParameterSpec(CMD_rsa_key_size.getInteger(), BigInteger.valueOf(CMD_exponent.getInteger())));
                } else {
                    kpg.initialize(CMD_rsa_key_size.getInteger());
                }
            }
            KeyPair key_pair = kpg.generateKeyPair();
            PrivateKey priv_key = key_pair.getPrivate();
            PublicKey subject_pub_key = key_pair.getPublic();

            ///////////////////////////////////////////////////////////////
            // Get signature algorithm
            ///////////////////////////////////////////////////////////////
            AsymSignatureAlgorithms certalg = CMD_sig_alg.getAlgorithm();

            ///////////////////////////////////////////////////////////////
            // Get the subject DN
            ///////////////////////////////////////////////////////////////
            certspec.setSubject(CMD_subject_dn.getString());

            ///////////////////////////////////////////////////////////////
            // Get the signing key and CA certificate(s)
            ///////////////////////////////////////////////////////////////
            PrivateKey sign_key = priv_key;  // Assume self-signed
            PublicKey issuer_pub_key = subject_pub_key;
            DistinguishedName issuer = certspec.getSubjectDistinguishedName();
            Vector<Certificate> cert_path = new Vector<Certificate>();
            if (!CMD_self_signed.found) {
                KeyStore ks = KeyStore.getInstance(CMD_ca_ks_type.getString());
                ks.load(new FileInputStream(CMD_ca_keystore.getString()), CMD_ca_ks_pass.toCharArray());
                String ca_key_alias = CMD_ca_key_alias.getString();
                if (ks.isKeyEntry(ca_key_alias)) {
                    Certificate[] cert_list = ks.getCertificateChain(ca_key_alias);
                    if (cert_list == null || cert_list.length == 0) {
                        bad("No certficates found for key alias: " + ca_key_alias);
                    }
                    issuer = DistinguishedName.subjectDN((X509Certificate) cert_list[0]);
                    issuer_pub_key = cert_list[0].getPublicKey();
                    if (CMD_ca_addpath.found) {
                        int n = cert_list.length;
                        if (!CMD_ca_addpath.getString().equals("all")) {
                            int l = CMD_ca_addpath.getInteger();
                            if (l < 1 || l > n) {
                                bad("The \"ca/addpath\" qualifier is out of range");
                            }
                            n = l;
                        }
                        for (int q = 0; q < n; q++) {
                            cert_path.add(cert_list[q]);
                        }
                    }
                } else {
                    bad("Bad CA key alias: " + ca_key_alias);
                }
                sign_key = (PrivateKey) ks.getKey(ca_key_alias, CMD_ca_key_pass.toCharArray());
                if (sign_key == null) {
                    bad("No signature key found for key alias: " + ca_key_alias);
                }
            }

            ///////////////////////////////////////////////////////////////
            // Get serial number
            ///////////////////////////////////////////////////////////////
            BigInteger serial = CMD_serial.found ? CMD_serial.getBigInteger() : createSerial();

            ///////////////////////////////////////////////////////////////
            // Get validity
            ///////////////////////////////////////////////////////////////
            Date start_date = CMD_valid_start.getDateTime();
            Date end_date = CMD_valid_end.getDateTime();

            ///////////////////////////////////////////////////////////////
            // Get certificate type
            ///////////////////////////////////////////////////////////////
            if (CMD_ca_cert.found) {
                certspec.setCACertificateConstraint();
            } else if (CMD_ee_cert.found) {
                certspec.setEndEntityConstraint();
            }

            ///////////////////////////////////////////////////////////////
            // Set key usage bits
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_key_usage.argvalue) {
                certspec.setKeyUsageBit(KeyUsageBits.getKeyUsageBit(arg));
            }

            ///////////////////////////////////////////////////////////////
            // Set extended key usage
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_eku.argvalue) {
                certspec.setExtendedKeyUsage(ExtendedKeyUsages.getExtendedKeyUsage(arg));
            }

            ///////////////////////////////////////////////////////////////
            // Set the SKI extension
            ///////////////////////////////////////////////////////////////
            if (CMD_ext_ski.found) {
                certspec.setSubjectKeyIdentifier();
            }

            ///////////////////////////////////////////////////////////////
            // Set the AKI extension
            ///////////////////////////////////////////////////////////////
            if (CMD_ext_aki.found) {
                certspec.setAuthorityKeyIdentifier();
            }

            ///////////////////////////////////////////////////////////////
            // Set certificate policy OIDs
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_certpol.argvalue) {
                certspec.addCertificatePolicyOID(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Set AIA OCSP responder URIs
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_ocsp.argvalue) {
                certspec.addOCSPResponderURI(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Get AIA CA issuer URIs
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_caissuers.argvalue) {
                certspec.addCAIssuersURI(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Get CRL distribution point URIs
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_cdp.argvalue) {
                certspec.addCRLDistributionPointURI(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Get SAN e-mail addresses
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_email.argvalue) {
                certspec.addEmailAddress(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Get SAN DNS names
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_dns.argvalue) {
                certspec.addDNSName(arg);
            }

            ///////////////////////////////////////////////////////////////
            // Get SAN IP addresses
            ///////////////////////////////////////////////////////////////
            for (String arg : CMD_ext_ip.argvalue) {
                certspec.addIPAddress(arg);
            }

            ///////////////////////////////////////////////////////////////
            // And now: Create the certificate...
            ///////////////////////////////////////////////////////////////
            X509Certificate signer_cert = ca.createCert(certspec, issuer, serial, start_date, end_date,
                    certalg, new CertificateSigner(sign_key, issuer_pub_key),
                    subject_pub_key);
            cert_path.insertElementAt(signer_cert, 0);

            ///////////////////////////////////////////////////////////////
            // The final: Write the whole thing out
            ///////////////////////////////////////////////////////////////
            KeyStore ks = CMD_out_ks_type.getString().equalsIgnoreCase("jks") ?
                    KeyStore.getInstance(CMD_out_ks_type.getString()) : KeyStore.getInstance(CMD_out_ks_type.getString(), sun_pkcs12);
            if (CMD_out_update.found) {
                ks.load(new FileInputStream(CMD_out_keystore.getString()), CMD_out_ks_pass.toCharArray());
            } else {
                ks.load(null, null);
            }
            FileOutputStream ofile = new FileOutputStream(CMD_out_keystore.getString());
            ks.setKeyEntry(CMD_out_key_alias.getString(),
                    priv_key,
                    CMD_out_pkey_pass.toCharArray(),
                    cert_path.toArray(new Certificate[0]));
            ks.store(ofile, CMD_out_ks_pass.toCharArray());
        } catch (GeneralSecurityException gse) {
            bad(gse.getMessage());
        }
    }


    public static void main(String argv[]) {
        try {
            String sun_pkcs12 = KeyStore.getInstance("PKCS12").getProvider().getName();
            CustomCryptoProvider.forcedLoad(true);
            CommandLineCA clca = new CommandLineCA();
            clca.decodeCommandLine(argv);
            clca.certify(sun_pkcs12);
        } catch (Exception ioe) {
            System.out.println("\n" + ioe.getMessage());
        }
    }
}

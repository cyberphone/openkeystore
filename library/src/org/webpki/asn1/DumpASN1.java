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
package org.webpki.asn1;

import java.io.*;

import org.webpki.util.ArrayUtil;

/**
 * Command line utility for viewing ASN.1 structures.
 * Will output a tree view.
 */
public class DumpASN1 {
    static void printUsageAndExit(String error) {
        if (error != null) {
            System.out.println("");
            System.out.println(error);
            System.out.println("");
        }
        System.out.println("Usage:");
        System.out.println("");
        System.out.println("  DumpASN1 [options] file");
        System.out.println("");
        System.out.println("    -x           Don't expand OCTET and BIT STRINGS");
        System.out.println("    -n           Don't show byte numbers");
        System.out.println("    -o nnn       Start parsing at decimal offset nnn");
        System.out.println("    -d file      Dump DER data to file");
        System.out.println("    -a file      Use alternate OID definition file");
        System.exit(0);
    }

    static int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException nfe) {
            printUsageAndExit("Malformed number " + s);
            return -1;
        }
    }


    public static void main(String[] args) throws Exception {
        if (args.length == 0) printUsageAndExit(null);

        int offset = 0;
        String oidfile = null;
        String outfile = null;
        boolean expand = true;
        boolean bytenum = true;
        String infile = null;

        for (int i = 0; i < args.length; i++) {
            String arg = args[i];
            if (arg.startsWith("-")) {
                if (infile != null) printUsageAndExit("unexpected option: " + arg);
                if (arg.equals("-x")) {
                    expand = false;
                } else if (arg.equals("-n")) {
                    bytenum = false;
                } else {
                    if (++i >= args.length) printUsageAndExit("Missing operand to option: " + arg);
                    String oper = args[i];
                    if (oper.startsWith("-")) printUsageAndExit("Bad operand to option: " + arg);
                    if (arg.equals("-o")) {
                        offset = parseInt(oper);
                    } else if (arg.equals("-d")) {
                        outfile = oper;
                    } else if (arg.equals("-a")) {
                        oidfile = oper;
                    } else printUsageAndExit("Unknown option: " + arg);
                }
            } else {
                if (infile != null) printUsageAndExit("Multiple input file: " + arg);
                infile = arg;
            }
        }
        if (infile == null) printUsageAndExit("Missing input file!");

        if (oidfile != null) ASN1ObjectID.tryReadOIDNames(oidfile);

        BaseASN1Object o = DerDecoder.decode(ArrayUtil.readFile(infile), offset);

        System.out.println(o.toString(expand, bytenum));

        if (outfile != null) {
            FileOutputStream fos = new FileOutputStream(outfile);
            o.encode(fos);
            fos.close();
        }
    }
}

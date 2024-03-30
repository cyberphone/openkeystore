/*
 *  Copyright 2006-2024 WebPKI.org (https://webpki.org).
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      https://apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 */
package org.webpki.infocard.test;

import org.webpki.util.ArrayUtil;

import org.webpki.crypto.test.DemoKeyStore;

import org.webpki.crypto.KeyStoreVerifier;

import org.webpki.infocard.InfoCardReader;

public class readcard
  {

    private static void show ()
      {
        System.out.println ("readcard in_file\n");
        System.exit (3);
      }

    public static void main (String args[]) throws Exception
      {
        if (args.length < 1) show ();
        KeyStoreVerifier verifier = new KeyStoreVerifier (DemoKeyStore.getCAKeyStore ());
        verifier.setTrustedRequired (false);
        new InfoCardReader (IO.readFile (args[0]), verifier);

      }
  }

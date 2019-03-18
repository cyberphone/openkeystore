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
package org.webpki.xmldsig;

import java.io.IOException;

import org.w3c.dom.Node;

import org.webpki.xmldsig.c14n.Canonicalizer;

/**
 * Any methods may throw a <code>RuntimeException</code> if specified nodes contain
 * a namespace declaration with a relative URI.
 */
public class XPathCanonicalizer {
    /*
     * Serializes the <var>node</var> and all descendants of the <var>node</var>.
     * The result of this method is the same as the result of <code>serializeSubset(XPathCanonicalizer.toNodeList(node), withComments)</code>.
     */
    public static byte[] serializeSubset(Node node, CanonicalizationAlgorithms algorithm) throws IOException {
        Canonicalizer c = Canonicalizer.getInstance(algorithm.getURI());
        byte[] r = c.canonicalizeSubtree(node);
//System.out.println ("CANON-WO+\n" + new String (r, "UTF-8") + "\nCANON-");
        return r;
    }

    public static byte[] serializeSubset(Node node, CanonicalizationAlgorithms algorithm, String inclusiveNamespaces) throws IOException {
        Canonicalizer c = Canonicalizer.getInstance(algorithm.getURI());
        byte[] r = c.canonicalizeSubtree(node, inclusiveNamespaces);
//System.out.println ("CANON-WI+\n" + new String (r, "UTF-8") + "\nCANON-");
        return r;
    }

    public static void isSupportedAlgorithm(CanonicalizationAlgorithms algorithm) throws IOException {
        Canonicalizer.getInstance(algorithm.getURI());
    }

}

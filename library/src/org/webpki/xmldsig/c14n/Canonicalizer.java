/*
 * Copyright  1999-2004 The Apache Software Foundation.
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
package org.webpki.xmldsig.c14n;


import java.io.OutputStream;
import java.util.HashMap;
import java.util.Map;

import org.w3c.dom.Node;


/**
 * @author Christian Geuer-Pollmann
 */
@SuppressWarnings("unchecked")
public class Canonicalizer {

    //J-
    /**
     * The output encoding of canonicalized data
     */
    public static final String ENCODING = "UTF-8";


    /*
     * XPath Expresion for selecting every node and continuos comments joined in only one node
     */
    public static final String XPATH_C14N_WITH_COMMENTS_SINGLE_NODE = "(.//. | .//@* | .//namespace::*)";


    /*
     * The URL defined in XML-SEC Rec for inclusive c14n <b>without</b> comments.
     */
    public static final String ALGO_ID_C14N_OMIT_COMMENTS = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315";
    /*
     * The URL defined in XML-SEC Rec for inclusive c14n <b>with</b> comments.
     */
    public static final String ALGO_ID_C14N_WITH_COMMENTS = ALGO_ID_C14N_OMIT_COMMENTS + "#WithComments";
    /*
     * The URL defined in XML-SEC Rec for exclusive c14n <b>without</b> comments.
     */
    public static final String ALGO_ID_C14N_EXCL_OMIT_COMMENTS = "http://www.w3.org/2001/10/xml-exc-c14n#";
    /*
     * The URL defined in XML-SEC Rec for exclusive c14n <b>with</b> comments.
     */
    public static final String ALGO_ID_C14N_EXCL_WITH_COMMENTS = ALGO_ID_C14N_EXCL_OMIT_COMMENTS + "WithComments";

    static Map _canonicalizerHash = null;

    protected CanonicalizerSpi canonicalizerSpi = null;
    //J+

    /*
     * Method init
     *
     */
    static {

        Canonicalizer._canonicalizerHash = new HashMap(10);
        Canonicalizer._canonicalizerHash.put(ALGO_ID_C14N_OMIT_COMMENTS,
                Canonicalizer20010315OmitComments.class);
        Canonicalizer._canonicalizerHash.put(ALGO_ID_C14N_WITH_COMMENTS,
                Canonicalizer20010315WithComments.class);
        Canonicalizer._canonicalizerHash.put(ALGO_ID_C14N_EXCL_OMIT_COMMENTS,
                Canonicalizer20010315ExclOmitComments.class);
        Canonicalizer._canonicalizerHash.put(ALGO_ID_C14N_EXCL_WITH_COMMENTS,
                Canonicalizer20010315ExclWithComments.class);
    }


    /*
     * Constructor Canonicalizer
     *
     * @param algorithmURI
     * @throws InvalidCanonicalizerException
     */
    private Canonicalizer(String algorithmURI)
            throws CanonicalizerException {

        try {
            Class implementingClass = getImplementingClass(algorithmURI);

            this.canonicalizerSpi =
                    (CanonicalizerSpi) implementingClass.newInstance();
            this.canonicalizerSpi.reset = true;
        } catch (Exception e) {
            Object exArgs[] = {algorithmURI};

            throw new CanonicalizerException(
                    "signature.Canonicalizer.UnknownCanonicalizer", exArgs);
        }
    }

    /*
     * Method getInstance
     *
     * @param algorithmURI
     * @return a Conicicalizer instance ready for the job
     * @throws CanonicalizerException
     */
    public static final Canonicalizer getInstance(String algorithmURI)
            throws CanonicalizerException {

        Canonicalizer c14nizer = new Canonicalizer(algorithmURI);

        return c14nizer;
    }


    /*
     * Method getURI
     *
     * @return the URI defined for this c14n instance.
     */
    public final String getURI() {
        return this.canonicalizerSpi.engineGetURI();
    }

    /*
     * Method getIncludeComments
     *
     * @return true if the c14n respect the comments.
     */
    public boolean getIncludeComments() {
        return this.canonicalizerSpi.engineGetIncludeComments();
    }


    /*
     * Canonicalizes the subtree rooted by <CODE>node</CODE>.
     *
     * @param node The node to canicalize
     * @return the result of the c14n.
     *
     * @throws CanonicalizerException
     */
    public byte[] canonicalizeSubtree(Node node)
            throws CanonicalizerException {
        return this.canonicalizerSpi.engineCanonicalizeSubTree(node);
    }

    /*
     * Canonicalizes the subtree rooted by <CODE>node</CODE>.
     *
     * @param node
     * @param inclusiveNamespaces
     * @return the result of the c14n.
     * @throws CanonicalizerException
     */
    public byte[] canonicalizeSubtree(Node node, String inclusiveNamespaces)
            throws CanonicalizerException {
        return this.canonicalizerSpi.engineCanonicalizeSubTree(node,
                inclusiveNamespaces);
    }


    /*
     * Sets the writter where the cannocalization ends. ByteArrayOutputStream if
     * none is setted.
     * @param os
     */
    public void setWriter(OutputStream os) {
        this.canonicalizerSpi.setWriter(os);
    }

    /*
     * Returns the name of the implementing {@link CanonicalizerSpi} class
     *
     * @return the name of the implementing {@link CanonicalizerSpi} class
     */
    public String getImplementingCanonicalizerClass() {
        return this.canonicalizerSpi.getClass().getName();
    }

    /*
     * Method getImplementingClass
     *
     * @param URI
     * @return the name of the class that implements the give URI
     */
    private static Class getImplementingClass(String URI) {
        return (Class) _canonicalizerHash.get(URI);
    }

    /*
     * Set the canonicalizator behaviour to not reset.
     *
     */
    public void notReset() {
        this.canonicalizerSpi.reset = false;
    }
}

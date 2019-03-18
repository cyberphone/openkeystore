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

import org.w3c.dom.Node;


/**
 * Base class which all Caninicalization algorithms extend.
 * <p>
 * $todo$ cange JavaDoc
 *
 * @author Christian Geuer-Pollmann
 */
public abstract class CanonicalizerSpi {

    //J-

    /**
     * Returns the URI of this engine.
     *
     * @return the URI
     */
    public abstract String engineGetURI();

    /* Returns the URI if include comments
     * @return true if include.
     */
    public abstract boolean engineGetIncludeComments();


    /*
     * C14n a node tree.
     *
     * @param rootNode
     * @return the c14n bytes
     * @throws CanonicalizerException
     */
    public abstract byte[] engineCanonicalizeSubTree(Node rootNode) throws CanonicalizerException;

    /*
     * C14n a node tree.
     *
     * @param rootNode
     * @param inclusiveNamespaces
     * @return the c14n bytes
     * @throws CanonicalizerException
     */
    public abstract byte[] engineCanonicalizeSubTree(Node rootNode, String inclusiveNamespaces) throws CanonicalizerException;

    /*
     * Sets the writter where the cannocalization ends. ByteArrayOutputStream if
     * none is setted.
     * @param os
     */
    public abstract void setWriter(OutputStream os);

    /* Reset the writter after a c14n */
    protected boolean reset = false;
    //J+
}

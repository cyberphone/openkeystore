
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

import java.io.IOException;

/**
 * Class CanonicalizerException
 *
 * @author Christian Geuer-Pollmann
 */
public class CanonicalizerException extends IOException {

    /*
      *
      */
    private static final long serialVersionUID = 1L;

    /*
     * Constructor CanonicalizerException
     *
     */
    public CanonicalizerException() {
        super();
    }

    /*
     * Constructor CanonicalizerException
     *
     * @param _msgID
     */
    public CanonicalizerException(String _msgID) {
        super(_msgID);
    }

    /*
     * Constructor CanonicalizerException
     *
     * @param _msgID
     * @param exArgs
     */
    public CanonicalizerException(String _msgID, Object exArgs[]) {
        super(_msgID);
    }

    /*
     * Constructor CanonicalizerException
     *
     * @param _msgID
     * @param _originalException
     */
    public CanonicalizerException(String _msgID, Exception _originalException) {
        super(_msgID);
    }

    /*
     * Constructor CanonicalizerException
     *
     * @param _msgID
     * @param exArgs
     * @param _originalException
     */
    public CanonicalizerException(String _msgID, Object exArgs[],
                                  Exception _originalException) {
        super(_msgID);
    }
}

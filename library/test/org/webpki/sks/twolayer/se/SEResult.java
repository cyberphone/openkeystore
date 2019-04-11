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
package org.webpki.sks.twolayer.se;

import java.security.GeneralSecurityException;

import org.webpki.sks.SKSException;

public abstract class SEResult {
    int status = 0;
    String message;
    
    void setError(Exception e, int error) {
        message = e.getMessage();
        this.status = error;
    }
    
    void setError(Exception e) {
        if (e instanceof SKSException) {
            setError(e, ((SKSException)e).getError());
        } else {
            setError(e, e instanceof GeneralSecurityException ? 
                                    SKSException.ERROR_CRYPTO : SKSException.ERROR_INTERNAL);
        }
    }
    
    public void testReturn() {
        if (status > 0) {
            throw new SKSException(message, status);
        }
    }
}

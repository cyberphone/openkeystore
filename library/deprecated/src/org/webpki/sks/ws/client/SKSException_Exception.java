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
package org.webpki.sks.ws.client;

        ///////////////////////////////////////////////
        // Generated by WSCreator 1.0 - Do not edit! //
        ///////////////////////////////////////////////

import javax.xml.ws.WebFault;

@SuppressWarnings("serial")
@WebFault(name="SKSException",
          targetNamespace="https://webpki.github.io/sks/v1.00")
public class SKSException_Exception extends Exception
  {
    /**
     * Java type that goes as soapenv:Fault detail element.
     */
    private SKSExceptionBean faultInfo;

    /**
     * @param message
     * @param faultInfo
     */
    public SKSException_Exception (String message, SKSExceptionBean faultInfo)
      {
         super (message);
         this.faultInfo = faultInfo;
      }

    /**
     * @param message
     * @param faultInfo
     * @param cause
     */
    public SKSException_Exception (String message, SKSExceptionBean faultInfo, Throwable cause)
      {
        super (message, cause);
        this.faultInfo = faultInfo;
      }

    /**
     * @return fault bean
     */
    public SKSExceptionBean getFaultInfo ()
      {
        return faultInfo;
      }
  }

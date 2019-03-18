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
package org.webpki.kg2xml;

import java.io.IOException;
import java.io.Serializable;

import java.util.LinkedHashSet;

import org.webpki.xml.DOMAttributeReaderHelper;
import org.webpki.xml.DOMWriterHelper;

public class BasicCapabilities implements Serializable
  {
    private static final long serialVersionUID = 1L;

    static final String BASIC_CAP_ALGORITHM       = "Algorithm";
    static final String BASIC_CAP_CLIENT_ATTRI    = "ClientAttribute";
    static final String BASIC_CAP_EXTENSION       = "Extension";
    static final String BASIC_CAP_PRE_QUERY       = "";
    static final String BASIC_CAP_POST_QUERY      = "SupportQuery";
    static final String BASIC_CAP_PRE_RESPONSE    = "Supported";
    static final String BASIC_CAP_POST_RESPONSE   = "s";

    LinkedHashSet<String> algorithms = new LinkedHashSet<String> ();

    LinkedHashSet<String> client_attributes = new LinkedHashSet<String> ();

    LinkedHashSet<String> extensions = new LinkedHashSet<String> ();
    
    private boolean read_only;
    
    BasicCapabilities (boolean read_only)
      {
        this.read_only = read_only;
      }

    static String[] getSortedAlgorithms (String[] algorithms) throws IOException
      {
        int i = 0;
        while (true)
          {
            if (i < (algorithms.length - 1))
              {
                if (algorithms[i].compareTo (algorithms[i + 1]) > 0)
                  {
                    String s = algorithms[i];
                    algorithms[i] = algorithms[i + 1];
                    algorithms[i + 1] = s;
                    i = 0;
                  }
                else
                  {
                    i++;
                  }
              }
            else
              {
                break;
              }
          }
        return algorithms;
      }


    private static void conditionalInput (DOMAttributeReaderHelper ah, LinkedHashSet<String> args, String tag, boolean query) throws IOException
      {
        String[] opt_uri_list = ah.getListConditional (tagName (tag, query));
        if (opt_uri_list != null)
          {
            for (String uri : opt_uri_list)
              {
                args.add (uri);
              }
          }
      }

    static void read (DOMAttributeReaderHelper ah, BasicCapabilities basic_capabilities, boolean query) throws IOException
      {
        conditionalInput (ah, basic_capabilities.algorithms, BASIC_CAP_ALGORITHM, query);
        conditionalInput (ah, basic_capabilities.client_attributes, BASIC_CAP_CLIENT_ATTRI, query);
        conditionalInput (ah, basic_capabilities.extensions, BASIC_CAP_EXTENSION, query);
      }


    private static void conditionalOutput (DOMWriterHelper wr, LinkedHashSet<String> arg_set, String tag, boolean query)
      {
        if (!arg_set.isEmpty ())
          {
            wr.setListAttribute (tagName (tag, query), arg_set.toArray (new String[0]));
          }
      }


    static void write (DOMWriterHelper wr, BasicCapabilities basic_capabilities, boolean query) throws IOException
      {
        conditionalOutput (wr,  basic_capabilities.algorithms, BASIC_CAP_ALGORITHM, query);
        conditionalOutput (wr,  basic_capabilities.client_attributes, BASIC_CAP_CLIENT_ATTRI, query);
        conditionalOutput (wr,  basic_capabilities.extensions, BASIC_CAP_EXTENSION, query);
      }

    
    void addCapability (LinkedHashSet<String> arg_set, String arg) throws IOException
      {
        if (!arg_set.add (arg))
          {
            throw new IOException ("Multiply defined argument: " + arg);
          }
      }


    public BasicCapabilities addAlgorithm (String algorithm) throws IOException
      {
        addCapability (algorithms, algorithm);
        return this;
      }

    
    public BasicCapabilities addClientAttribute (String client_attribute) throws IOException
      {
        addCapability (client_attributes, client_attribute);
        return this;
      }

    
    public BasicCapabilities addExtension (String extension) throws IOException
      {
        addCapability (extensions, extension);
        return this;
      }


   public String[] getAlgorithms () throws IOException
      {
        return algorithms.toArray (new String[0]);
      }

    
    public String[] getClientAttributes () throws IOException
      {
        return client_attributes.toArray (new String[0]);
      }


    public String[] getExtensions () throws IOException
      {
        return extensions.toArray (new String[0]);
      }


    static String tagName (String tag, boolean query)
      {
        return query ? 
            BASIC_CAP_PRE_QUERY + tag + BASIC_CAP_POST_QUERY
                     :
            BASIC_CAP_PRE_RESPONSE + tag + BASIC_CAP_POST_RESPONSE;
      }

    public void checkCapabilities (BasicCapabilities actual_capabilities) throws IOException
      {
         checkCompliance (algorithms, actual_capabilities.algorithms);
         checkCompliance (client_attributes, actual_capabilities.client_attributes);
         checkCompliance (extensions, actual_capabilities.extensions);
      }


    private void checkCompliance (LinkedHashSet<String> requested_features, LinkedHashSet<String> supported_features) throws IOException
      {
        for (String feature : supported_features)
          {
            if (!requested_features.contains (feature))
              {
                throw new IOException ("Unexpected feature: " + feature);
              }
          }
      }
  }

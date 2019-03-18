package org.webpki.sks.ws.client;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.xml.ws.Holder;

import javax.xml.ws.BindingProvider;

import org.webpki.crypto.CertificateInfo;
import org.webpki.crypto.CertificateUtil;

public class SKSWSClient
  {
    private SKSWSProxy proxy;
    
    private String port;
    
    
    public SKSWSClient (String port)
      {
        this.port = port;
      }

    /**
     * Factory method. Each WS call should use this method.
     * 
     * @return A handle to a fresh WS instance
     */
    public SKSWSProxy getSKSWS ()
    {
        if (proxy == null)
        {
            synchronized (this)
            {
                SKSWS service = new SKSWS ();
                SKSWSProxy temp_proxy = service.getSKSWSPort ();
                Map<String,Object> request_object = ((BindingProvider) temp_proxy).getRequestContext ();
                request_object.put (BindingProvider.ENDPOINT_ADDRESS_PROPERTY, port);
                proxy = temp_proxy;
            }
        }
        return proxy;
    }

    static void bad (String msg)
    {
     throw new RuntimeException (msg); 
    }
    
    /**
     * Test method. Use empty argument list for help.
     * 
     * @param args
     *            Command line arguments
     * @throws  
     * @throws SKSExceptionBean 
     */
    public static void main (String args[])
    {
        if (args.length != 1)
        {
            System.out.println ("SKSWSClient port");
            System.exit (3);
        }
        SKSWSClient client = new SKSWSClient (args[0]);
        SKSWSProxy proxy = client.getSKSWS ();
        System.out.println ("Version=" + proxy.getVersion ());

        System.out.println ("abortProvisioningSession testing...");
        try
          {
            proxy.abortProvisioningSession (5);
            bad ("Should have thrown");
          }
        catch (SKSException_Exception e)
          {
            if (e.getFaultInfo ().getError () != 4)
              {
                bad ("error ex");
              }
            if (!e.getFaultInfo ().getMessage ().equals ("bad"))
              {
                bad ("message ex");
              }
          }

        System.out.println ("getKeyProtectionInfo testing...");
        Holder<Byte> blah = new Holder<Byte> ();
        Holder<String> prot = new Holder<String> ();
        prot.value = "yes";
        Holder<List<byte[]>> certls = new Holder<List<byte[]>> ();
        try
          {
            if (proxy.getKeyProtectionInfo (4, prot, blah, certls) != 800)
              {
                bad ("return");
              }
            if (!prot.value.equals ("yes@"))
              {
                bad ("prot");
              }
            if (blah.value != 6)
              {
                bad ("blah");
              }
            if (certls.value == null || certls.value.size () != 2)
              {
                bad ("certs");
              }
            for (byte[] cert : certls.value)
              {
                System.out.println ("CERT=" + new CertificateInfo (CertificateUtil.getCertificateFromBlob (cert), false).getSubject ());
              }
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
        catch (IOException e)
          {
            // TODO Auto-generated catch block
            e.printStackTrace();
          }
        System.out.println ("setCertificatePath testing...");
        try
          {
            proxy.setCertificatePath (8,certls.value, new byte[]{4,6});
            proxy.setCertificatePath (3,null, new byte[]{4,6,7});
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
        System.out.println ("getCertPath testing...");
        try
          {
            List<byte[]> ret = proxy.getCertPath (true);
            if (ret.size () != 2)
              {
                bad("certs");
              }
            ret = proxy.getCertPath (false);
            if (!ret.isEmpty ())
              {
                bad("certs");
              }
          }
        catch (SKSException_Exception e)
          {
            bad (e.getMessage ());
          }
    }    

  }

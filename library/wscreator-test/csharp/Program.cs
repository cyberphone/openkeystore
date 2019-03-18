using System;
using System.Collections.Generic;
using System.Text;
using System.Reflection;
using org.webpki.sks.ws.client;
using System.Xml;
using System.Security.Cryptography.X509Certificates;

namespace wstest
{
    //TODO
    public class MyErrorHandler : System.ServiceModel.Dispatcher.IErrorHandler
    {
        public bool HandleError(System.Exception error)
        {
            System.Console.WriteLine("Yes!");
            return false;
        }

        public void ProvideFault(System.Exception error,
                                 System.ServiceModel.Channels.MessageVersion version,
                                 ref System.ServiceModel.Channels.Message msg)
        {
            System.Console.WriteLine("No!");
        }
    }

    public class MyClientExceptionBehavior : System.ServiceModel.Description.IEndpointBehavior
    {
        public void AddBindingParameters(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        { }

        public void ApplyClientBehavior(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Dispatcher.ClientRuntime behavior)
        {
            //Add the inspector

            behavior.CallbackDispatchRuntime.ChannelDispatcher.ErrorHandlers.Add(new MyErrorHandler ());

        }

        public void ApplyDispatchBehavior(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        { }

        public void Validate(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint)
        { }
    }

    public class MyClientInspectorBehavior : System.ServiceModel.Description.IEndpointBehavior
    {
        public void AddBindingParameters(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Channels.BindingParameterCollection bindingParameters)
        { }

        public void ApplyClientBehavior(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Dispatcher.ClientRuntime behavior)
        {
            //Add the inspector

            behavior.MessageInspectors.Add(new CustomMessageInspector());
        }

        public void ApplyDispatchBehavior(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint, System.ServiceModel.Dispatcher.EndpointDispatcher endpointDispatcher)
        { }

        public void Validate(System.ServiceModel.Description.ServiceEndpoint serviceEndpoint)
        { }
    }

    public class CustomMessageInspector : System.ServiceModel.Dispatcher.IClientMessageInspector
    {
        #region IClientMessageInspector Members


        public void AfterReceiveReply(ref System.ServiceModel.Channels.Message reply, object correlationState)
        {
            Console.WriteLine(reply.ToString());
        }


        public object BeforeSendRequest(ref System.ServiceModel.Channels.Message request, System.ServiceModel.IClientChannel channel)
        {
            Console.WriteLine(request.ToString());

            return null;
        }


        #endregion

    }
 

    class Program
    {
        static void bad(string msg)
        {
            throw new System.ArgumentException(msg);
        }

        static void Main(string[] args)
        {
            System.Console.WriteLine("Hi there!");
/*
// External config
            System.ServiceModel.BasicHttpBinding wsBinding = new System.ServiceModel.BasicHttpBinding();
            wsBinding.SendTimeout = System.TimeSpan.FromMinutes(5);
//            wsBinding.TransactionFlow = true;
            System.ServiceModel.EndpointAddress endpointAddress = new
              System.ServiceModel.EndpointAddress("http://localhost:8080/securekeystore");
            ws = new SKSWSProxy(wsBinding, endpointAddress);
 */
// We rather used the default created by the definition file.
            SKSWSProxy ws = SKSWSProxy.getDefaultSKSWSProxy();
            System.Console.WriteLine("Assembly=" + Assembly.GetAssembly(ws.GetType()).FullName);
            //            ws.Endpoint.Behaviors.Add(new MyClientInspectorBehavior());
//            ws.Endpoint.Behaviors.Add(new MyClientExceptionBehavior());
            System.Console.WriteLine(ws.getVersion());
            System.Console.WriteLine("abortProvisiongSession testing...");
            ws.abortProvisioningSession(6);
            try
            {
                ws.abortProvisioningSession(5);
                bad("Failed to abort");
            }
            catch (System.ServiceModel.FaultException<SKSException> e)
            {
                if (e.Detail.getMessage() != "bad")
                {
                    bad("Exception message wrong: " + e.Detail.getMessage());
                }
                if (e.Detail.getError() != 4)
                {
                    bad("Exception error wrong: " + e.Detail.getError());
                }
            }
             string prot = "yes";
            sbyte b1;
            X509Certificate2[] x509_certificates;
            System.Console.WriteLine("getKeyProtectionInfo testing...");
            if (ws.getKeyProtectionInfo(5, ref prot, out b1, out x509_certificates) != 800)
            {
                bad("Bad return gkpi");
            }
            if (prot != "yes@")
            {
                bad("Prot data wrong: " + prot);
            }
            if (b1 != 7)
            {
                bad("Blah data wrong: " + b1);
            }
            if (x509_certificates == null || x509_certificates.Length != 2)
            {
                bad("Cert return error");
            }
            foreach (X509Certificate2 cert in x509_certificates)
                {
                    System.Console.WriteLine("CERT=" + cert.SubjectName.Name);
                }
            byte[] mac = new byte[]{2,7,9,8,4};
            ws.setCertificatePath(3, x509_certificates, mac);
            ws.setCertificatePath(4, null, mac);
            x509_certificates = ws.getCertPath(true);
            System.Console.WriteLine("getCertPath testing...");
            if (x509_certificates == null || x509_certificates.Length != 2)
            {
                bad("getCertPath");
            }
            x509_certificates = ws.getCertPath(false);
            if (x509_certificates != null)
            {
                bad("getCertPath");
            }
        }
    }
}

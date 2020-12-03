using System;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TPMImport
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("PFX to TPM Importer");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TPMImport [-user] PFXPath PFXPassword");
                return;
            }

            int iArgPos = 0;

            bool fUser = args[iArgPos].Equals("-user", StringComparison.InvariantCultureIgnoreCase);
            if (fUser) ++iArgPos;
            bool fVerbose = args[iArgPos].Equals("-v", StringComparison.InvariantCultureIgnoreCase);
            if (fVerbose) ++iArgPos;

            string sPFXPath = args[iArgPos++];
            string sPassword = args[iArgPos++];
                
            //var parameters = new CngKeyCreationParameters()
            //{
            //    Provider = 
            //    //CngProvider.MicrosoftSoftwareKeyStorageProvider,
            //     new CngProvider("Microsoft Platform Crypto Provider"),
            //    KeyCreationOptions = CngKeyCreationOptions.None,
            //    ExportPolicy = CngExportPolicies.None
            //};

            //parameters.Parameters.Add(new CngProperty("Length", BitConverter.GetBytes(2048), CngPropertyOptions.None));

            //CngKey key = CngKey.Create(CngAlgorithm.Rsa, "RSATestKey2", parameters);

            //try
            //{

            //    // byte[] test = key.Export(CngKeyBlobFormat.Pkcs8PrivateBlob);
            //}
            //finally
            //{
            //    key.Delete();
            //}

            X509Certificate2 cert = new X509Certificate2(sPFXPath, sPassword, X509KeyStorageFlags.Exportable);
            RSACng rsaCNG = new RSACng();
            rsaCNG.FromXmlString(cert.GetRSAPrivateKey().ToXmlString(true));
            var keyData = rsaCNG.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
            var keyParams = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.None,
                KeyCreationOptions = fUser ? CngKeyCreationOptions.None : CngKeyCreationOptions.MachineKey,
                Provider =
                new CngProvider("Microsoft Platform Crypto Provider"),
                //CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            keyParams.Parameters.Add(new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, keyData, CngPropertyOptions.None));
            var key = CngKey.Create(CngAlgorithm.Rsa, $"TPM-Import-Key-{cert.Thumbprint}", keyParams);

            if (fVerbose)
            {
                Console.WriteLine($"Key Is Closed: {key.Handle.IsClosed}; Is Invalid: {key.Handle.IsInvalid}; Export Policy: {key.ExportPolicy}; Is Ephemeral: {key.IsEphemeral}");
            }

            rsaCNG = new RSACng(key);
            X509Certificate2 certOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));
            certOnly = certOnly.CopyWithPrivateKey(rsaCNG);
            X509Store store = new X509Store(StoreName.My, fUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certOnly);
            store.Close();

        }

    }
}

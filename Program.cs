using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using DotNetCode;
using Microsoft.Win32.SafeHandles;

namespace TPMImport
{
    class Program
    {
        [SupportedOSPlatform("windows")]
        static void Main(string[] args)
        {
            Console.WriteLine("PFX to TPM Importer");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TPMImport [-user] [-v] PFXPath PFXPassword");
                return;
            }

            int iArgPos = 0;

            bool fUser = args[iArgPos].Equals("-user", StringComparison.InvariantCultureIgnoreCase);
            if (fUser) ++iArgPos;
            bool fVerbose = args[iArgPos].Equals("-v", StringComparison.InvariantCultureIgnoreCase);
            if (fVerbose) ++iArgPos;

            string sPFXPath = args[iArgPos++];

            string sPassword = "";
            if (args.Length > iArgPos)
                sPassword = args[iArgPos++];

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
            RSACng keyFromPFx = new RSACng();
            keyFromPFx.FromXmlString(cert.GetRSAPrivateKey().ToXmlString(true));
            var keyData = keyFromPFx.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
            var keyParams = new CngKeyCreationParameters
            {
                ExportPolicy = CngExportPolicies.None,
                KeyCreationOptions = fUser ? CngKeyCreationOptions.None : CngKeyCreationOptions.MachineKey,
                Provider =
                new CngProvider("Microsoft Platform Crypto Provider"),
                //CngProvider.MicrosoftSoftwareKeyStorageProvider
            };
            keyParams.Parameters.Add(new CngProperty(CngKeyBlobFormat.GenericPrivateBlob.Format, keyData, CngPropertyOptions.None));
            //keyParams.Parameters.Add(new CngProperty("Key Type", new byte[] { 0, 0, 0, 32 }, CngPropertyOptions.None));



            //RawSecurityDescriptor sdEveryoneCanRead = new RawSecurityDescriptor("A;;GRFR;;;S-1-1-0");
            //byte[] binSDL = new byte[sdEveryoneCanRead.BinaryLength];
            //sdEveryoneCanRead.GetBinaryForm(binSDL, 0);
            //keyParams.Parameters.Add(new CngProperty("Security Descr", binSDL, (CngPropertyOptions) 0x44)); // 0x44 = DACL_SECURITY_INFORMATION | NCRYPT_SILENT_FLAG

            CngKey key = CngKey.Create(CngAlgorithm.Rsa, $"TPM-Import-Key-{cert.Thumbprint}", keyParams);
            //            key = CngKey.Open($"TPM-Import-Key-{cert.Thumbprint}", new CngProvider("Microsoft Platform Crypto Provider"), CngKeyOpenOptions.MachineKey);

            CngProperty propMT = key.GetProperty("Key Type", CngPropertyOptions.None);
            byte[] baMT = propMT.GetValue();

            if (fVerbose)
            {
                Console.WriteLine($"Key is reported as Machine Key (always false): {key.IsMachineKey}; Key Is Closed: {key.Handle.IsClosed}; Is Invalid: {key.Handle.IsInvalid}; Export Policy: {key.ExportPolicy}; Is Ephemeral: {key.IsEphemeral}");
            }

            X509Certificate2 certOnly = new X509Certificate2(cert.Export(X509ContentType.Cert));
            certOnly = CertificateExtensionsCommon.CopyWithPersistedCngKeyFixed(certOnly, key);
            X509Store store = new X509Store(StoreName.My, fUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(certOnly);
            store.Close();

        }
     }
}

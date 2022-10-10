using DotNetCode;
using Microsoft.Win32.SafeHandles;
using System;
using System.Linq;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TPMImport
{
    internal class Program
    {
        [SupportedOSPlatform("windows")]
        private static void Main(string[] args)
        {
            Console.WriteLine("PFX to TPM Importer");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TPMImport [-user] [-v] PFXPath [PFXPassword]");
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

            using X509Certificate2 cert = new(sPFXPath, sPassword, X509KeyStorageFlags.Exportable);
            using RSACng keyFromPFx = new();
            keyFromPFx.FromXmlString(cert.GetRSAPrivateKey().ToXmlString(true));
            byte[] keyData = keyFromPFx.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
            CngKeyCreationParameters keyParams = new()
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

            if (fVerbose)
                Console.WriteLine($"Creating RSA CngKeyObject with TPM-Import-Key-{cert.Thumbprint}");

            using CngKey key = CngKey.Create(CngAlgorithm.Rsa, $"TPM-Import-Key-{cert.Thumbprint}", keyParams);

            //            key = CngKey.Open($"TPM-Import-Key-{cert.Thumbprint}", new CngProvider("Microsoft Platform Crypto Provider"), CngKeyOpenOptions.MachineKey);

            CngProperty propMT = key.GetProperty("Key Type", CngPropertyOptions.None);
            //byte[] baMT = propMT.GetValue();

            if (fVerbose)
            {
                Console.WriteLine($"Key is reported as Machine Key (always false): {key.IsMachineKey}; Key Is Closed: {key.Handle.IsClosed}; Is Invalid: {key.Handle.IsInvalid}; Export Policy: {key.ExportPolicy}; Is Ephemeral: {key.IsEphemeral}");
            }

            using X509Certificate2 certOnly = new(cert.Export(X509ContentType.Cert));
            using X509Certificate2 copiedCertificate = CertificateExtensionsCommon.CopyWithPersistedCngKeyFixed(certOnly, key);

            if (fVerbose)
                using (RSACng keyOfCopiedCertificate = copiedCertificate.GetRSAPrivateKey() as RSACng)
                {
                    CngProperty NewExportPolicy = keyOfCopiedCertificate.Key.GetProperty("Export Policy", CngPropertyOptions.None);
                    string exportPolicyValue = string.Join('-',
                        NewExportPolicy.GetValue()
                            .Select(valueByte => valueByte.ToString()));
                    Console.WriteLine($"Export Policy of copied key: {exportPolicyValue}");

                }

            using X509Store store = new(StoreName.My, fUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);
            store.Add(copiedCertificate);
            store.Close();

        }
    }
}

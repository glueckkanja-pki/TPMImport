using DotNetCode;
using Microsoft.Win32.SafeHandles;
using System;
using System.IO;
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
        /** Delete both the certificate & private key in TPM */
        [SupportedOSPlatform("windows")]
        private static void DeleteCngCertificate(bool fUser, string Thumbprint)
        {
            using X509Store store = new X509Store(StoreName.My, fUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
            store.Open(OpenFlags.ReadWrite);

            // search for a matching CNG certificate stored in TPM
            foreach (X509Certificate2 cert in store.Certificates)
            {
                if (cert.Thumbprint != Thumbprint)
                    continue; // thumbprint mismatch

                if (!cert.HasPrivateKey)
                    continue; // private key missing

                var priv_key = (RSACng)cert.GetRSAPrivateKey();
                if (priv_key == null)
                    continue; // unsupported key type

                if (priv_key.Key.Provider != CngProvider.MicrosoftPlatformCryptoProvider)
                    continue; // key not stored in TPM

                Console.WriteLine("Deleting " + cert.Subject + " with name " + priv_key.Key.KeyName + "\n");
                // delete certificate
                store.Remove(cert);
                // delete associated CNG key
                priv_key.Key.Delete();

                return;
            }
        }

        [SupportedOSPlatform("windows")]
        private static void Main(string[] args)
        {
            Console.WriteLine("PFX to TPM Importer");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TPMImport [-user] [-delete] [-v] PFXPath [PFXPassword]");
                return;
            }

            int iArgPos = 0;

            bool fUser = args[iArgPos].Equals("-user", StringComparison.InvariantCultureIgnoreCase);
            if (fUser) ++iArgPos;
            bool fDelete = args[iArgPos].Equals("-delete", StringComparison.InvariantCultureIgnoreCase);
            if (fDelete) ++iArgPos;
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

            X509KeyStorageFlags pfxImportFlags = X509KeyStorageFlags.Exportable;
            if (fUser)
                pfxImportFlags |= X509KeyStorageFlags.UserKeySet;
            using X509Certificate2 cert = new(sPFXPath, sPassword, pfxImportFlags);

            if (fDelete)
            {
                DeleteCngCertificate(fUser, cert.Thumbprint);
                return;
            }

            using var rsaPrivKey = (RSACng)cert.GetRSAPrivateKey();
            byte[] keyData = rsaPrivKey.Key.Export(CngKeyBlobFormat.GenericPrivateBlob);
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

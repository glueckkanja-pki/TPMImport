using DotNetCode;
using System;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace TPMImport
{
    internal static class Program
    {
        private static string _passwordForTemporaryKeys;
        private static string PasswordForTemporaryKeys
        {
            get
            {
                if (null == _passwordForTemporaryKeys)
                {
                    byte[] binPw = new byte[40];
                    using (RandomNumberGenerator rng = RandomNumberGenerator.Create())
                        rng.GetBytes(binPw);
                    _passwordForTemporaryKeys = Convert.ToBase64String(binPw);
                }

                return _passwordForTemporaryKeys;
            }
        }

        private static void PrintExportPolicy(CngKey key)
        {
            CngProperty NewExportPolicy = key.GetProperty("Export Policy", CngPropertyOptions.None);
            string exportPolicyValue = string.Join('-',
                NewExportPolicy.GetValue()
                    .Select(valueByte => valueByte.ToString()));
            Console.WriteLine($"Export Policy of copied key: {exportPolicyValue}");
        }

        private static void DeleteIfOnTPM(X509Store store, X509Certificate2 cert, CngKey key)
        {
            if (key.Provider != CngProvider.MicrosoftPlatformCryptoProvider)
                return; // key not stored in TPM

            Console.WriteLine("Deleting " + cert.Subject + " with name " + key.KeyName + "\n");
            // delete certificate
            store.Remove(cert);
            // delete associated CNG key
            key.Delete();
        }

        /** Delete both the certificate & private key in TPM */
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

                var priv_key_rsa = (RSACng)cert.GetRSAPrivateKey();
                if (priv_key_rsa != null)
                    DeleteIfOnTPM(store, cert, priv_key_rsa.Key);

                var priv_key_ecdsa = (ECDsaCng)cert.GetECDsaPrivateKey();
                if (priv_key_ecdsa != null)
                    DeleteIfOnTPM(store, cert, priv_key_ecdsa.Key);

                return;
            }
        }

        private static void Main(string[] args)
        {
            Console.WriteLine("PFX to TPM Importer");

            if (args.Length < 2)
            {
                Console.WriteLine("Usage: TPMImport [-user] [-delete] [-v] [PFXPath|-b EncodedPfx] [PFXPassword]");
                return;
            }

            int iArgPos = 0;

            bool fUser = args[iArgPos].Equals("-user", StringComparison.InvariantCultureIgnoreCase);
            if (fUser) ++iArgPos;
            bool fDelete = args[iArgPos].Equals("-delete", StringComparison.InvariantCultureIgnoreCase);
            if (fDelete) ++iArgPos;
            bool fVerbose = args[iArgPos].Equals("-v", StringComparison.InvariantCultureIgnoreCase);
            if (fVerbose) ++iArgPos;

            byte[] binPfx;
            bool fBase64 = args[iArgPos].Equals("-b", StringComparison.InvariantCultureIgnoreCase);
            if (fBase64)
            {
                ++iArgPos;
                binPfx = Convert.FromBase64String(args[iArgPos++]);
            }
            else
            {
                string sPFXPath = args[iArgPos++];
                binPfx = File.ReadAllBytes(sPFXPath);
            }

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
            using X509Certificate2 cert = new(binPfx, sPassword, pfxImportFlags);

            if (fDelete)
            {
                DeleteCngCertificate(fUser, cert.Thumbprint);
                return;
            }

            using var rsaPrivKey = (RSACng)cert.GetRSAPrivateKey();
            if (!rsaPrivKey.Key.ExportPolicy.HasFlag(CngExportPolicies.AllowPlaintextExport))
            {
                // workaround for missing AllowPlaintextExport
                PbeParameters encParams = new(PbeEncryptionAlgorithm.Aes128Cbc, HashAlgorithmName.SHA256, 1);
                byte[] exportedKey = rsaPrivKey.ExportEncryptedPkcs8PrivateKey(PasswordForTemporaryKeys, encParams);
                rsaPrivKey.ImportEncryptedPkcs8PrivateKey(PasswordForTemporaryKeys, exportedKey, out _);
            }

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

            CngKey key = null;
            string keyName = $"TPM-Import-Key-{cert.Thumbprint}";

            try
            {
                key = CngKey.Create(CngAlgorithm.Rsa, keyName, keyParams);


                //            key = CngKey.Open($"TPM-Import-Key-{cert.Thumbprint}", new CngProvider("Microsoft Platform Crypto Provider"), CngKeyOpenOptions.MachineKey);

                //CngProperty propMT = key.GetProperty("Key Type", CngPropertyOptions.None);
                //byte[] baMT = propMT.GetValue();

                if (fVerbose)
                {
                    Console.WriteLine($"Key is reported as Machine Key (always false): {key.IsMachineKey}; Key Is Closed: {key.Handle.IsClosed}; Is Invalid: {key.Handle.IsInvalid}; Export Policy: {key.ExportPolicy}; Is Ephemeral: {key.IsEphemeral}");
                }

                using X509Certificate2 cngCert = new(cert.Export(X509ContentType.Cert));
                CertificateExtensionsCommon.AddCngKey(cngCert, key);

                if (fVerbose)
                {
                    {
                        using var keyOfCopiedCertificate = (RSACng)cngCert.GetRSAPrivateKey();
                        if (keyOfCopiedCertificate != null)
                            PrintExportPolicy(keyOfCopiedCertificate.Key);
                    }
                    {
                        using var keyOfCopiedCertificate = (ECDsaCng)cngCert.GetECDsaPrivateKey();
                        if (keyOfCopiedCertificate != null)
                            PrintExportPolicy(keyOfCopiedCertificate.Key);
                    }
                }

                using X509Store store = new(StoreName.My, fUser ? StoreLocation.CurrentUser : StoreLocation.LocalMachine);
                store.Open(OpenFlags.ReadWrite);
                store.Add(cngCert);
                store.Close();
            }
            catch (CryptographicException cex) when ((uint)cex.HResult == 0x8009000F)
            {
                throw new InvalidOperationException($"Private key with name '{keyName}' already exists.", cex);
            }
            finally
            {
                key?.Dispose();
            }
        }
    }
}

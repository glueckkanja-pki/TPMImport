using System;
using System.Runtime.InteropServices;
using System.Runtime.Versioning;
using System.Security;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCode
{
    [SupportedOSPlatform("windows")]
    internal static class CertificateExtensionsCommon
    {
        public static bool IsMachineKey(CngKey cngKey)
        {
            // the IsMachineKey property seem to be fixed on Win11
            if (Environment.OSVersion.Version.Build >= 22000)
                return cngKey.IsMachineKey;

            // the following logic don't work on Win11 where GetProperty("Key Type"..) returns [32, 0, 0, 0] for LocalMachine keys
            CngProperty propMT = cngKey.GetProperty("Key Type", CngPropertyOptions.None);
            byte[] baMT = propMT.GetValue();
            return (baMT[0] & 1) == 1; // according to https://docs.microsoft.com/en-us/windows/win32/seccng/key-storage-property-identifiers, which defines NCRYPT_MACHINE_KEY_FLAG differently than ncrypt.h
        }

        [SecurityCritical]
        internal static void AddCngKey(X509Certificate2 x509Certificate, CngKey cngKey)
        {
            if (string.IsNullOrEmpty(cngKey.KeyName))

                return;

            bool isMachineKey = IsMachineKey(cngKey);
            X509Native.CRYPT_KEY_PROV_INFO crypt_KEY_PROV_INFO = default;
            crypt_KEY_PROV_INFO.pwszContainerName = cngKey.KeyName;
            crypt_KEY_PROV_INFO.pwszProvName = cngKey.Provider.Provider;
            crypt_KEY_PROV_INFO.dwProvType = 0;
            crypt_KEY_PROV_INFO.dwFlags = (int)(isMachineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None);
            crypt_KEY_PROV_INFO.cProvParam = 0;
            crypt_KEY_PROV_INFO.rgProvParam = System.IntPtr.Zero;
            crypt_KEY_PROV_INFO.dwKeySpec = GuessKeySpec(cngKey.Provider, cngKey.KeyName, isMachineKey, cngKey.AlgorithmGroup);
            using SafeCertContextHandle certificateContext = X509Native.GetCertificateContext(x509Certificate);
            if (!X509Native.SetCertificateKeyProvInfo(certificateContext, ref crypt_KEY_PROV_INFO))
            {
                int lastWin32Error = Marshal.GetLastWin32Error();
                throw new CryptographicException(lastWin32Error);
            }
        }

        private static int GuessKeySpec(CngProvider provider, string keyName, bool machineKey, CngAlgorithmGroup algorithmGroup)
        {
            if (provider == CngProvider.MicrosoftSoftwareKeyStorageProvider || provider == CngProvider.MicrosoftSmartCardKeyStorageProvider)
            {
                return 0;
            }
            CngKeyOpenOptions openOptions = machineKey ? CngKeyOpenOptions.MachineKey : CngKeyOpenOptions.None;
            using (CngKey.Open(keyName, provider, openOptions))
            {
                return 0;
            }
        }

        //private static bool TryGuessKeySpec(CspParameters cspParameters, CngAlgorithmGroup algorithmGroup, out int keySpec)
        //{
        //	if (algorithmGroup == CngAlgorithmGroup.Rsa)
        //	{
        //		return CertificateExtensionsCommon.TryGuessRsaKeySpec(cspParameters, out keySpec);
        //	}
        //	if (algorithmGroup == CngAlgorithmGroup.Dsa)
        //	{
        //		return CertificateExtensionsCommon.TryGuessDsaKeySpec(cspParameters, out keySpec);
        //	}
        //	keySpec = 0;
        //	return false;
        //}

        //private static bool TryGuessRsaKeySpec(CspParameters cspParameters, out int keySpec)
        //{
        //	int[] array = new int[]
        //	{
        //		1,
        //		24,
        //		12,
        //		2
        //	};
        //	foreach (int providerType in array)
        //	{
        //		cspParameters.ProviderType = providerType;
        //		try
        //		{
        //			using (new RSACryptoServiceProvider(cspParameters))
        //			{
        //				keySpec = cspParameters.KeyNumber;
        //				return true;
        //			}
        //		}
        //		catch (CryptographicException)
        //		{
        //		}
        //	}
        //	keySpec = 0;
        //	return false;
        //}

        //private static bool TryGuessDsaKeySpec(CspParameters cspParameters, out int keySpec)
        //{
        //	int[] array = new int[]
        //	{
        //		13,
        //		3
        //	};
        //	foreach (int providerType in array)
        //	{
        //		cspParameters.ProviderType = providerType;
        //		try
        //		{
        //			using (new DSACryptoServiceProvider(cspParameters))
        //			{
        //				keySpec = cspParameters.KeyNumber;
        //				return true;
        //			}
        //		}
        //		catch (CryptographicException)
        //		{
        //		}
        //	}
        //	keySpec = 0;
        //	return false;
        //}
    }
}

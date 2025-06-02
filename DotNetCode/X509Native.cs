using System;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Cryptography.X509Certificates;

namespace DotNetCode
{
    internal static class X509Native
    {
        // Token: 0x06000A03 RID: 2563 RVA: 0x000244E0 File Offset: 0x000226E0
        [SecurityCritical]
        internal static bool SetCertificateKeyProvInfo(SafeCertContextHandle certificateContext, ref X509Native.CRYPT_KEY_PROV_INFO provInfo)
        {
            return X509Native.UnsafeNativeMethods.CertSetCertificateContextProperty(certificateContext, X509Native.CertificateProperty.KeyProviderInfo, X509Native.CertSetPropertyFlags.None, ref provInfo);
        }

        // Token: 0x06000A05 RID: 2565 RVA: 0x000244FB File Offset: 0x000226FB
        [SecuritySafeCritical]
        internal static SafeCertContextHandle DuplicateCertContext(IntPtr context)
        {
            return X509Native.UnsafeNativeMethods.CertDuplicateCertificateContext(context);
        }

        // Token: 0x06000A06 RID: 2566 RVA: 0x00024504 File Offset: 0x00022704
        [SecuritySafeCritical]
        internal static SafeCertContextHandle GetCertificateContext(X509Certificate certificate)
        {
            SafeCertContextHandle result = X509Native.DuplicateCertContext(certificate.Handle);
            GC.KeepAlive(certificate);
            return result;
        }

        // Token: 0x0200035F RID: 863
        internal enum CertificateProperty
        {
            // Token: 0x04000F6D RID: 3949 (CERT_KEY_PROV_INFO_PROP_ID)
            KeyProviderInfo = 2,
            // Token: 0x04000F6E RID: 3950 (CERT_KEY_CONTEXT_PROP_ID)
            KeyContext = 5,
            // Token: 0x04000F6F RID: 3951 (CERT_NCRYPT_KEY_HANDLE_PROP_ID)
            NCryptKeyHandle = 78
        }

        // Token: 0x02000360 RID: 864
        [Flags]
        internal enum CertSetPropertyFlags
        {
            // Token: 0x04000F71 RID: 3953
            CERT_SET_PROPERTY_INHIBIT_PERSIST_FLAG = 1073741824,
            // Token: 0x04000F72 RID: 3954
            None = 0
        }

        // Token: 0x02000362 RID: 866
        internal struct CRYPT_KEY_PROV_INFO
        {
            // Token: 0x04000F76 RID: 3958
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszContainerName;

            // Token: 0x04000F77 RID: 3959
            [MarshalAs(UnmanagedType.LPWStr)]
            internal string pwszProvName;

            // Token: 0x04000F78 RID: 3960
            internal int dwProvType;

            // Token: 0x04000F79 RID: 3961
            internal int dwFlags;

            // Token: 0x04000F7A RID: 3962
            internal int cProvParam;

            // Token: 0x04000F7B RID: 3963
            internal IntPtr rgProvParam;

            // Token: 0x04000F7C RID: 3964 (AT_KEYEXCHANGE=1, AT_SIGNATURE=2)
            internal int dwKeySpec;
        }

        // Token: 0x02000365 RID: 869
        [SuppressUnmanagedCodeSecurity]
        //		[SecurityCritical(SecurityCriticalScope.Everything)]
        //		[HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
        public static class UnsafeNativeMethods
        {
            // Token: 0x06001B80 RID: 7040
            [DllImport("crypt32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            internal static extern bool CertSetCertificateContextProperty(SafeCertContextHandle pCertContext, X509Native.CertificateProperty dwPropId, X509Native.CertSetPropertyFlags dwFlags, [In] ref X509Native.CRYPT_KEY_PROV_INFO pvData);

            // Token: 0x06001B82 RID: 7042
            [DllImport("crypt32.dll")]
            internal static extern SafeCertContextHandle CertDuplicateCertificateContext(IntPtr certContext);
        }
    }
}

# TPMImport
Imports certificates from PFX files into the Microsoft Platform Crypto Provider, so that the private key is stored in TPM.

## TPMImport Usage

`TPMImport [-user] [-delete] [-v] [PFXPath|-b EncodedPfx] [PFXPassword]`


## Relation to certutil

TPMImport conceptually does the same as `certutil [-user] -csp TPM -p password -importPFX PFXFile NoExport`. However, [certutil](https://learn.microsoft.com/en-us/windows-server/administration/windows-commands/certutil) has a bug on Windows 10 and possibly some older versions of Windows 11 where it produces the following error when importing an RSA key:

```
CertUtil: -importPFX command FAILED: 0x80090027 (-2146893785 NTE_INVALID_PARAMETER)
CertUtil: The parameter is incorrect.
```

If you leave away the NoExport, it produces the error

```
CertUtil: -importPFX command FAILED: 0x80090029 (-2146893783 NTE_NOT_SUPPORTED)
CertUtil: The requested operation is not supported.
```

If you have a recent version of Windows 11 and want to import an RSA key into the TPM, it is likely better to use certutil instead of TPMImport, as it comes pre-installed with Windows.

Using certutil to import certificates with ECDSA key might also fail on Windows. It might initially work, but `certutil -store MY` would show `ERROR: Could not verify certificate public key against private key`. Others have seen a `NTE_BAD_TYPE` error during import already. TPMImport correctly imports these keys.

## Known Issues

When deleting the certificate via the Windows UI or similar means, the TPM still keeps the private key. This is different than other KSPs and CSPs and likely depends only on the KSP and not the way TPMImport imports the key. Read [Issue #4](https://github.com/glueckkanja-pki/TPMImport/issues/4) for more details.

Keys stored in the TPM can be listed through the `certutil [-user] -csp TPM -key` command and leaked keys can be deleted with `certutil [-user] -csp TPM -delkey TPM-Import-Key-<thumbprint> `.

## License

TPMImport is available under the [GPL](LICENSE).

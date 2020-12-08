# TPMImport
Imports certificates from PFX files into the Microsoft Platform Crypto Provider.

This is the same as

certutil -user -csp TPM -p password -importPFX PFXFile NoExport

But certutil has a bug and at least on some systems produces the error 

```
CertUtil: -importPFX command FAILED: 0x80090027 (-2146893785 NTE_INVALID_PARAMETER)
CertUtil: The parameter is incorrect.
```

If you leave away the NoExport, it produces the error

```
CertUtil: -importPFX command FAILED: 0x80090029 (-2146893783 NTE_NOT_SUPPORTED)
CertUtil: The requested operation is not supported.
```

## License

TPMImport is available under the [GPL](LICENSE).

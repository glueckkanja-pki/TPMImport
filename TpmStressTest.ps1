# This script generates many certificates and stores them in the Platform KSP to find out how many certificates can be stored before the maximum TPM capacity is reached

for ($x = 1; $x -le 2050; $x++) {
    # Generate a new self-signed certificate in the Software KSP (directly in Platform KSP does not work at least sometimes)
    $cert = New-SelfSignedCertificate -Subject "CN=TPM-TestCert-$x" -CertStoreLocation "Cert:\CurrentUser\My" -KeyExportPolicy Exportable -KeySpec Signature -KeyLength 2048 -KeyAlgorithm RSA -HashAlgorithm SHA256 -NotAfter (Get-Date).AddYears(1)
    # Export the certificate to a file in the temp directory
    $certPath = "$env:TEMP\TPM-TestCert-$x.pfx"
    $cert | Export-PfxCertificate -FilePath $certPath -Password (ConvertTo-SecureString -String "password" -Force -AsPlainText)
    # Delete the certificate from the Software KSP
    Remove-Item -Path "Cert:\CurrentUser\My\$($cert.Thumbprint)" -Force
    # Import the certificate into the Platform KSP
    .\TPMImport.exe -user $certPath "password"
    # Delete the certificate file
    Remove-Item -Path $certPath -Force
}


if ($delete) {
    # Delete all certificates from the Platform KSP and also the private keys from the TPM
    $certs = Get-ChildItem -Path "Cert:\CurrentUser\My" | Where-Object { $_.Subject -like "CN=TPM-TestCert-*" }

    foreach ($cert in $certs) {
        $thumbprint = $cert.Thumbprint
        $cert | Remove-Item -Force
        certutil -user -csp TPM -delkey "TPM-Import-Key-$thumbprint"
    }
}
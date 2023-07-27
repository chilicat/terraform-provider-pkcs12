---
page_title: "PKCS12 From PEM resource"
description: |-
  Creates a PKCS12 archive for given PEM files
---

# pkcs12_from_pem Resource/Data Source

Creates a PKCS12 archive for given PEM files


## Example Usage

```hcl
resource "pkcs12_from_pem" "my_pkcs12" {
  password = "mypassword"
  cert_pem = tls_self_signed_cert.my_cert.cert_pem
  private_key_pem  = tls_private_key.my_private_key.private_key_pem
  # private_key_pass = "key-pass"
  ca_pem = file("./ca.pem")
}

resource "local_file" "result" {
  filename = "/mypath/certificates.p12"
  content_base64     = pkcs12_from_pem.my_pkcs12.result
}
```

## Argument Reference
* `password` - (Required) the archive password 
* `cert_pem` - (Required) The certificate in PEM format
* `private_key_pem` - (Required) The private key in PEM format
* `private_key_pass` - (Optional) Password to decrypt private key
* `ca_pem` - (Optional) The CA (chain) in PEM format

## Attribute Reference

* `result` - The created PKCS12 archive (base64 encoded)

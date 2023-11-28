package pkcs12

import (
	"context"
	"crypto/x509"
	"fmt"
	"strings"

	"encoding/base64"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"software.sslmate.com/src/go-pkcs12"
)

func resourcePkcs12() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourcePkcs12Create,
		ReadContext:   resourcePkcs12Read,
		UpdateContext: resourcePkcs12Update,
		DeleteContext: resourcePkcs12Delete,
		Schema: map[string]*schema.Schema{

			"cert_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Certificate or certificate chain",
			},
			"private_key_pem": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Private Key",
			},
			"private_key_pass": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Default:     "",
				Description: "Private Key password",
			},
			"password": {
				Type:        schema.TypeString,
				Required:    true,
				Sensitive:   true,
				ForceNew:    true,
				Description: "Keystore password",
			},
			"ca_pem": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				Default:     "",
				Description: "CA (or list of CAs)",
				// TODO: All fields are ForceNew or Computed w/out Optional, Update is superfluous
				// Why is not possible to force new if optional is true?
				// ForceNew: true,

			},
			"encoding": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   false,
				Default:     "modern2023",
				Description: "Set encoding",
			},

			"result": {
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func decodeCerts(certStr []byte) (*x509.Certificate, []*x509.Certificate, error) {
	certificates, err := decodeCertificates(certStr)
	if err != nil {
		return nil, nil, err
	}
	if len(certificates) == 0 {
		return nil, nil, fmt.Errorf("cert_pem must contain at least one certificate")
	}
	certificate := certificates[0]
	caListAndIntermediate := []*x509.Certificate{}
	if len(certificates) > 1 {
		caListAndIntermediate = certificates[1:]
	}
	return certificate, caListAndIntermediate, nil
}

func resourcePkcs12Create(ctx context.Context, d *schema.ResourceData, _ interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	var err error
	certStr := d.Get("cert_pem").(string)
	privatekeyStr := d.Get("private_key_pem").(string)
	privatekeyPass := d.Get("private_key_pass").(string)
	password := d.Get("password").(string)
	caStr := d.Get("ca_pem").(string)

	encoding := d.Get("encoding").(string)
	encoder := encodingMap[encoding]
	if encoder == nil {
		return diag.FromErr(fmt.Errorf("unsupported encoding: %q. Supported: %q", encoding, toKeys(encodingMap)))
	}

	certificate, caListAndIntermediate, err := decodeCerts([]byte(certStr))

	if err != nil {
		return diag.FromErr(err)
	}

	// Read private filekey, fails if given data does not contain any private key
	privateKeys, err := decodePrivateKeysFromPem([]byte(privatekeyStr), []byte(privatekeyPass))
	if err != nil {
		return diag.FromErr(err)
	}
	if len(privateKeys) != 1 {
		return diag.FromErr(fmt.Errorf("private_key_pem must contain exactly one private key"))
	}

	// Read CA (chain), can be empty.
	if caStr != "" {
		list, err := decodePemCA([]byte(caStr))
		if err != nil {
			return diag.FromErr(err)
		}
		caListAndIntermediate = append(caListAndIntermediate, list...)
	}

	res, err := encoder.Encode(privateKeys[0], certificate, caListAndIntermediate, password)
	if err != nil {
		return diag.FromErr(err)
	}
	d.SetId(hashForState("pkcs12_" + password + certStr + privatekeyStr + caStr + encoding))
	d.Set("result", base64.StdEncoding.EncodeToString(res))
	return diags
}

func resourcePkcs12Read(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourcePkcs12Update(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	return nil
}

func resourcePkcs12Delete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	d.SetId("")
	return nil
}

var (
	encodingMap = map[string]*pkcs12.Encoder{
		"modern":     pkcs12.Modern,
		"modern2023": pkcs12.Modern2023,
		"legacyDES":  pkcs12.LegacyDES,
		"legacyRC2":  pkcs12.LegacyRC2,
	}
)

func toKeys(m map[string]*pkcs12.Encoder) string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	return strings.Join(keys, ", ")
}

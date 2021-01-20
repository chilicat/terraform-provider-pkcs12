package pkcs12

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"

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
			"cert_pem": &schema.Schema{
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				ForceNew:  true,
			},
			"private_key_pem": &schema.Schema{
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				ForceNew:  true,
			},
			"password": &schema.Schema{
				Type:      schema.TypeString,
				Required:  true,
				Sensitive: true,
				ForceNew:  true,
			},
			"ca_pem": &schema.Schema{
				Type:      schema.TypeString,
				Optional:  true,
				Sensitive: true,
				Default:   "",

				// TODO: All fields are ForceNew or Computed w/out Optional, Update is superfluous
				// Why is not possible to force new if optional is true?
				// ForceNew: true,

			},
			"result": &schema.Schema{
				Type:     schema.TypeString,
				Computed: true,
			},
		},
	}
}

func resourcePkcs12Create(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	var diags diag.Diagnostics
	certStr := d.Get("cert_pem").(string)
	privatekey := d.Get("private_key_pem").(string)
	password := d.Get("password").(string)
	caStr := d.Get("ca_pem").(string)

	var cert tls.Certificate

	// Read certificate
	if err := loadCertficates(&cert, []byte(certStr)); err != nil {
		return diag.FromErr(err)
	}

	// Read private filekey
	if err := loadCertficates(&cert, []byte(privatekey)); err != nil {
		return diag.FromErr(err)
	}

	if cert.PrivateKey == "" {
		return diag.Errorf("Cannot find private key")
	}
	// Read CA (chain)
	var ca tls.Certificate
	if caStr != "" {
		if err := loadCertficates(&ca, []byte(caStr)); err != nil {
			return diag.FromErr(err)
		}
	}

	var caList []*x509.Certificate
	for _, c := range ca.Certificate {
		c1, err := x509.ParseCertificate(c)
		if err != nil {
			return diag.FromErr(err)
		}
		caList = append(caList, c1)
	}

	c1, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return diag.FromErr(err)
	}
	res, err := pkcs12.Encode(rand.Reader, cert.PrivateKey, c1, caList, password)
	d.SetId(hashForState("pkcs12_" + password + certStr + privatekey + caStr))
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

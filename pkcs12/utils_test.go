package pkcs12

import (
	"testing"
)

var (
	privateKeysExamplePass      = []byte("testpass")
	privateKeysEncryptedExample = []byte(`
-----BEGIN RSA PRIVATE KEY-----
Proc-Type: 4,ENCRYPTED
DEK-Info: AES-256-CBC,1DB3F6C25F244D3250C9FE4EC7EDBA76

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
-----END RSA PRIVATE KEY-----
`)
	privateKeyExample = []byte(`
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
`)

	allInOnePem = []byte(
		string(certificateExample) + "\n" + string(caCert) + "\n",
	)

	certificateExample = []byte(`
-----BEGIN CERTIFICATE-----
MIIFGDCCAwACCQC8bLGIm8aWOzANBgkqhkiG9w0BAQsFADBOMQ0wCwYDVQQDDARt
eWNuMQswCQYDVQQGEwJERTELMAkGA1UECAwCREUxDjAMBgNVBAcMBU15TG9jMRMw
EQYDVQQKDApvcGVyYXRpb25zMB4XDTIzMDcyNzA5MjY0OVoXDTI4MDcyNjA5MjY0
OVowTjENMAsGA1UEAwwEbXljbjELMAkGA1UEBhMCREUxCzAJBgNVBAgMAkRFMQ4w
DAYDVQQHDAVNeUxvYzETMBEGA1UECgwKb3BlcmF0aW9uczCCAiIwDQYJKoZIhvcN
AQEBBQADggIPADCCAgoCggIBAMJlBBbW0sdbHCymdhm/U1uYNA1vBZbUsNGGcY+A
6jpUlvNZLpqtAtFA+7FyCxsq1C4t6HK5mwM5TWIiYP03uxMHM9PLz4+Foy6o7R1L
bUusf71i5w1p9Wj5k1I/HHAmuNlhheadmf+AwySKQsBol4iEUVtk8wrxv9Fbubt4
8tedLBM24JfKN3gpqPbWDXAXmyLxsJglpnSvqOoOYEKUNLHFMuaRiMQGaLn8pJnx
v6otxZwOPZvKu5m/qsmfyfRQtuihqKquCVYUakPHlBcIPqTYvgHc8X+IzvzUgFWb
4Gj6BWXtt0QIoZvNkWu+Fx6dQqHscWI/wgkzIW0Wru3FFmjmgqmCwG5Dso3dhrxo
nunlTbWGbNhrLpWLF3OZhv+AYa99fvLejQr6x1eNnSjs0a6R7W2M2xwfLcdt7HEd
gcBzk2RDTuKzpy/up4qNt0/knkozy4+VBBDkJyMc3r132JRmVDV9MuZSh/KNW6RR
wKKXmNQztr/2t4Lrr5K9/61zvy/aZMfh3M3ZKRpsVclqZDkXf7JSL3rFTFotANmI
eKbJ7TmFdFMg43DRqHxoRzLlFaBeXDdkJkkCIGibE0J2rW6qlOx7Y0HAuDsYhMEh
LOF6LqaWuoaEPaZex/jlgKcpmqyymHxT6ha3ATOruOsEjajF3Xn72lXEYinlc8HF
BFH1AgMBAAEwDQYJKoZIhvcNAQELBQADggIBAKUIfotUkWCL5ZAD5GMmhDyTlJkk
5wTActFNeKN3+e0LS+DzYlydWpcGTXQ3s0+iSKU5HZhDVMCs/RHKhFwz9+OuqBZO
rkVrnJXJW2HZT3lYWNsX+7IjSDNXet0FQoJ0pPNXiyVzpOs0Cy1RxgGIC6ABW/7T
iDvcivKuLk/AS70Kj7jpmTv7uAm0fnWgkfe2TbNJFliiTxIvAdBhCc88qH7ZJL52
JessLVQuWJmyZpHogZsda7SZ/vb5h62K4GGzewwj5WzrgbAlg9bov1ZYF+SArefX
+q3GI/nYwNvH0HkzL6pXFhVmwpTgSJv22K0ByRrnIU9uZph2j6PP2dWFr7IOu2s5
Ah7wp09yxYvao7/THDXCT0Zaz3FMf9jNksdDthGuBB4lky93L2NePFON4Js5s3i1
VXLsVBzqJUguYt1BYxXezXCkcflzj5OgRooDbF2xBBW62fj89B9925+GV0Qzosyz
klTVBfUuVW6ntociZZ4Iu5rMIUHrk8oXXHik1x2JNhb6ics9AnrmEIoPtodjZzyT
ZUCljyB/dxiWwfB6msqKTzeO8Pixm+cgoxnHvnR6WHDH7FolJR21WdT7t+1P3iq1
MnX2CqiJS6TA6qGCCNk44ZiJ0EgE6EM2afaQCk9eS2YyC/tlEWG3qaIdGPItPOKP
Jxt2+wqV4uHoFDPS
-----END CERTIFICATE-----
`)

	caCert = []byte(`
-----BEGIN CERTIFICATE-----
MIICGTCCAZ+gAwIBAgIQCeCTZaz32ci5PhwLBCou8zAKBggqhkjOPQQDAzBOMQsw
CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xJjAkBgNVBAMTHURp
Z2lDZXJ0IFRMUyBFQ0MgUDM4NCBSb290IEc1MB4XDTIxMDExNTAwMDAwMFoXDTQ2
MDExNDIzNTk1OVowTjELMAkGA1UEBhMCVVMxFzAVBgNVBAoTDkRpZ2lDZXJ0LCBJ
bmMuMSYwJAYDVQQDEx1EaWdpQ2VydCBUTFMgRUNDIFAzODQgUm9vdCBHNTB2MBAG
ByqGSM49AgEGBSuBBAAiA2IABMFEoc8Rl1Ca3iOCNQfN0MsYndLxf3c1TzvdlHJS
7cI7+Oz6e2tYIOyZrsn8aLN1udsJ7MgT9U7GCh1mMEy7H0cKPGEQQil8pQgO4CLp
0zVozptjn4S1mU1YoI71VOeVyaNCMEAwHQYDVR0OBBYEFMFRRVBZqz7nLFr6ICIS
B4CIfBFqMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
BAMDA2gAMGUCMQCJao1H5+z8blUD2WdsJk6Dxv3J+ysTvLd6jLRl0mlpYxNjOyZQ
LgGheQaRnUi/wr4CMEfDFXuxoJGZSZOoPHzoRgaLLPIxAJSdYsiJvRmEFOml+wG4
DXZDjC5Ty3zfDBeWUA==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIICHDCCAaOgAwIBAgIQBT9uoAYBcn3tP8OjtqPW7zAKBggqhkjOPQQDAzBQMQsw
CQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQsIEluYy4xKDAmBgNVBAMTH0Rp
Z2lDZXJ0IFNNSU1FIEVDQyBQMzg0IFJvb3QgRzUwHhcNMjEwMTE1MDAwMDAwWhcN
NDYwMTE0MjM1OTU5WjBQMQswCQYDVQQGEwJVUzEXMBUGA1UEChMORGlnaUNlcnQs
IEluYy4xKDAmBgNVBAMTH0RpZ2lDZXJ0IFNNSU1FIEVDQyBQMzg0IFJvb3QgRzUw
djAQBgcqhkjOPQIBBgUrgQQAIgNiAAQWnVXlttT7+2drGtShqtJ3lT6I5QeftnBm
ICikiOxwNa+zMv83E0qevAED3oTBuMbmZUeJ8hNVv82lHghgf61/6GGSKc8JR14L
HMAfpL/yW7yY75lMzHBrtrrQKB2/vgSjQjBAMB0GA1UdDgQWBBRzemuW20IHi1Jm
wmQyF/7gZ5AurTAOBgNVHQ8BAf8EBAMCAYYwDwYDVR0TAQH/BAUwAwEB/zAKBggq
hkjOPQQDAwNnADBkAjA3RPUygONx6/Rtz3zMkZrDbnHY0iNdkk2CQm1cYZX2kfWn
CPZql+mclC2YcP0ztgkCMAc8L7lYgl4Po2Kok2fwIMNpvwMsO1CnO69BOMlSSJHW
Dvu8YDB8ZD8SHkV/UT70pg==
-----END CERTIFICATE-----
`)

	ecPrivateKey = []byte(`
-----BEGIN EC PARAMETERS-----
MIGiAgEBMCwGByqGSM49AQECIQD////////////////////////////////////+
///8LzAGBAEABAEHBEEEeb5mfvncu6xVoGKVzocLBwKb/NstzijZWfKBWxb4F5hI
Otp3JqPEZV2k+/wOEQio/Re0SKaFVBmcR9CP+xDUuAIhAP//////////////////
//66rtzmr0igO7/SXozQNkFBAgEB
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MIIBEwIBAQQgTT3OMYeuQZDjn3zE88wT6Kr+bM3b4rL++lJFa+80M2yggaUwgaIC
AQEwLAYHKoZIzj0BAQIhAP////////////////////////////////////7///wv
MAYEAQAEAQcEQQR5vmZ++dy7rFWgYpXOhwsHApv82y3OKNlZ8oFbFvgXmEg62ncm
o8RlXaT7/A4RCKj9F7RIpoVUGZxH0I/7ENS4AiEA/////////////////////rqu
3OavSKA7v9JejNA2QUECAQGhRANCAAQqk8ptTVDVDURvuxHug5DUAm50IdoNKSdQ
hczq27UIZwO/WqvmllOZ1EKkTAQUNzWS/wQpNa/5fGMDD6qUNdW3
-----END EC PRIVATE KEY-----

`)

	rsaKey = []byte(`
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA72ObzM8bnHTCJj50djkEdF+TVlg8z7CkwSPjPANjXNhBWHVB
8HBUtUKLJsoHGTj35+9Uq6CuGymB3d0s5r5LBa3ywF0QeP57Qa1f9gkEupFArgek
FYgXXi8u5HNoaT7FCgNum6fkXF7DsjSidGe0Z1VYj2HKavah51r8URv38QTswUqq
icXLlPD5K27PNNYRUUhZ54q2VwyZMgeLPHTYBAyC99OY8KlnVjkzqir8B2pGKsAO
iBaoc6FJ+0C6CR32rU3hfdBnbh8+c4S5i5lYaQz+iP6dU+CMxq39JGFQuao66UnK
gpUgiKVvT5QYI/92oofCahD88RM3HXejTO+TXwIDAQABAoIBAQCSXW627LJPGLxU
Mb93QSlOFdm54z1bJv+070JSQSgRbk+VzCvC3IuOP99gmgl5DHHWp2g3f4i0Js62
XjLD6flowZA4uS4HLGEkKOMRRTZU89Z+EUHrwEe5WFPtbfqazrwegTaxiReAupgg
bzocvgN5Yp9BG2NtvtoC4IiA9v7DpzZVPFKbpVlEYWMle+RGBtzD/9h0u2k3Psux
MTU9YcRyvej5+3yyri/YV+mzve3QXaZdACR8AfQbFT3bV9M50rsGOFt+3VsH0gwr
2IrdQNLgxqON9NIHlW6ORe5TbAXhwTiAkKEJcHjjRVROtNnerdRWtZSTDxk7d/d2
bv012WZRAoGBAP9PQpHVdEvqPV2L1WRSKCaSqaHwJFimuQCM0KDJytgdD9Rzlz8B
GAjv0k1zreZj7Ap4vGsxNBYGY4k5HpPWI5HvQ00zXxgPX4uSkYCVE2U7RjODuJq0
KzFLDGDOELW6sIj299Yx4mCnCYW8vHNmYiZCbOugWTV5yjYUWbOJA4LbAoGBAPAJ
U9SgFC+NgCE7z+PgoK/iouGXnpnHHy0o8ju1vX/XbzJbXrF5btPSuDP+Fyj+sMbg
xvKSlFIsk+gVjEBH0ZbP1O2CXWp6DDldMf6YlYMiXoM7ZaxfSXmQOcneNzH3GOjD
lcfV+N8CXphfGSnfuE5+YCZGCJvQXPt5i2RhqH7NAoGAbVvd/+mWrw3eyzsiZJ5s
ZFleH+dlKjP/+qRWmQjWwktwhGge2PX2/Zz8UADE9HLIoJOm4aNp1CVYbWbyGhEX
m2MJSQBAM2YiXv6hJJq2fB4vq9E4OcwC1FJ5Mt4RekZFZ+WhszYa6ZujEI4Pir7I
O+soDKXakHVikFeXNLfzsRECgYEAyocUNFLctUKu2VueDKd67OxMggtrxlQ7+d6S
g87UFQmwyMxPGW9cE124DiZVZEGA5kzBj+odOzhhk3Ca5aGzNYwmHD/ikfRoW/5G
MIqNnBdjp1Z2cvnzBJ6sI6da6s2SNtLPjcz8Ly3Qor+ae7pHx/LZLXHp0Y385jGn
awr7IAECgYEA/U6FebKQOADU8mdjo6ir1ghTzJD/nivjeYi4rNH7ObTW1JbmjF9D
AB3dJTEmWSgUTDaCpY1aFR0NFMfdkOsPwT2tHtUBddx3Em5dZc3CNlI3j5CJ9x2C
ogrIU+Z+JyIPd47DI8acKlzGeR2Wn5hQrdQApC0Ve2Lvmbz8Hj67pJ4=
-----END RSA PRIVATE KEY-----

`)
)

func TestDecodeCertificateAllInOne(t *testing.T) {
	cert, list, err := decodeCerts(allInOnePem)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(list) != 2 {
		t.Log(len(list))
		t.Error("certificate list must a certificate and ca's")
		t.FailNow()
	}

	if cert.IsCA {
		t.Error("certificate[0] must not be a CA")
	}

	if !list[0].IsCA {
		t.Error("certificate[0] must be a CA")
	}
	if !list[1].IsCA {
		t.Error("certificate[1] must be a CA")
	}
}

func TestDecodeCertificate(t *testing.T) {
	cert, list, err := decodeCerts(certificateExample)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(list) != 0 {
		t.Error("certificateExample must not contain any CAs")
		t.FailNow()
	}

	if cert.IsCA {
		t.Error("certificate must not ba a CA")
	}
}

func TestDecodeCA(t *testing.T) {
	c, err := decodePemCA(caCert)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(c) != 2 {
		t.Error("must return one CA")
		t.FailNow()
	}

	for i, ca := range c {
		if !ca.IsCA {
			t.Errorf("certificate[%d] must be a CA", i)
		}
	}

}

func TestDecodePrivateKeysEncypted(t *testing.T) {
	keys, err := decodePrivateKeysFromPem(privateKeysEncryptedExample, privateKeysExamplePass)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(keys) != 1 {
		t.Error("result must contain one private key")
		t.FailNow()
	}
}

func TestDecodePrivateKeys(t *testing.T) {
	keys, err := decodePrivateKeysFromPem(privateKeyExample, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
	if len(keys) != 1 {
		t.Error("result must contain one private key")
		t.FailNow()
	}
}

func TestDecodePrivateKeysEC(t *testing.T) {

	_, err := decodePrivateKeysFromPem(ecPrivateKey, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

}

func TestDecodePrivateKeysRSA(t *testing.T) {

	_, err := decodePrivateKeysFromPem(rsaKey, nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}
}

func TestDecodePrivateBadString(t *testing.T) {

	_, err := decodePrivateKeysFromPem([]byte("cdcdklmcdlkmcd\nxxsx\ncdcdc"), nil)
	if err != nil {
		t.Error(err)
		t.FailNow()
	}

}

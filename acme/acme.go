package acme

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/traefik/traefik/v2/pkg/provider/acme"
	"github.com/traefik/traefik/v2/pkg/types"
)

// Convert a acme.json file.
func Convert(srcFile, dstFile, resolverName string) error {
	src, err := os.Open(srcFile)
	if err != nil {
		return err
	}
	defer func() { _ = src.Close() }()

	oldData := StoredData{}
	err = json.NewDecoder(src).Decode(&oldData)
	if err != nil {
		return err
	}

	data := acme.StoredData{}

	if oldData.Account != nil {
		data.Account = &acme.Account{
			Email:        oldData.Account.Email,
			Registration: oldData.Account.Registration,
			PrivateKey:   oldData.Account.PrivateKey,
			KeyType:      oldData.Account.KeyType,
		}
	}

	for _, c := range oldData.Certificates {
		data.Certificates = append(data.Certificates, &acme.CertAndStore{
			Certificate: acme.Certificate{
				Domain: types.Domain{
					Main: c.Domain.Main,
					SANs: c.Domain.SANs,
				},
				Certificate: c.Certificate,
				Key:         c.Key,
			},
			Store: "default",
		})
	}

	err = os.MkdirAll(filepath.Dir(dstFile), 0o755)
	if err != nil {
		return err
	}

	dst, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer func() { _ = dst.Close() }()

	encoder := json.NewEncoder(dst)
	encoder.SetIndent("", "  ")

	return encoder.Encode(map[string]*acme.StoredData{resolverName: &data})
}

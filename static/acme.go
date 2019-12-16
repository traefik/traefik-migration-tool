package static

import (
	"fmt"

	"github.com/containous/traefik/v2/pkg/config/static"
	"github.com/containous/traefik/v2/pkg/provider/acme"
)

func migrateACME(oldCfg Configuration) map[string]static.CertificateResolver {
	if oldCfg.ACME == nil {
		return nil
	}

	if oldCfg.ACME.EntryPoint != "" {
		fmt.Printf("The entry point (%s) defined in the ACME configuration must be converted manually. See https://docs.traefik.io/routing/routers/#certresolver\n", oldCfg.ACME.EntryPoint)
	}

	return map[string]static.CertificateResolver{
		"default": {
			ACME: &acme.Configuration{
				Email:         oldCfg.ACME.Email,
				CAServer:      oldCfg.ACME.CAServer,
				Storage:       oldCfg.ACME.Storage,
				KeyType:       oldCfg.ACME.KeyType,
				DNSChallenge:  migrateDNSChallenge(oldCfg),
				HTTPChallenge: migrateHTTPChallenge(oldCfg),
				TLSChallenge:  migrateTLSChallenge(oldCfg),
			},
		},
	}
}

func migrateHTTPChallenge(oldCfg Configuration) *acme.HTTPChallenge {
	if oldCfg.ACME.HTTPChallenge == nil {
		return nil
	}

	return &acme.HTTPChallenge{
		EntryPoint: oldCfg.ACME.HTTPChallenge.EntryPoint,
	}
}

func migrateTLSChallenge(oldCfg Configuration) *acme.TLSChallenge {
	if oldCfg.ACME.TLSChallenge == nil {
		return nil
	}

	return &acme.TLSChallenge{}
}

func migrateDNSChallenge(oldCfg Configuration) *acme.DNSChallenge {
	if oldCfg.ACME.DNSChallenge == nil {
		return nil
	}

	return &acme.DNSChallenge{
		Provider:                oldCfg.ACME.DNSChallenge.Provider,
		DelayBeforeCheck:        convertDuration(oldCfg.ACME.DNSChallenge.DelayBeforeCheck, 0),
		Resolvers:               oldCfg.ACME.DNSChallenge.Resolvers,
		DisablePropagationCheck: oldCfg.ACME.DNSChallenge.DisablePropagationCheck,
	}
}

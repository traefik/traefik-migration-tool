package static

import (
	"fmt"
	"time"

	"github.com/containous/flaeg/parse"
	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/ping"
	"github.com/traefik/traefik/v2/pkg/tls"
	"github.com/traefik/traefik/v2/pkg/types"
)

func migrateConfiguration(oldCfg Configuration) static.Configuration {
	if oldCfg.Retry != nil {
		fmt.Println("Retry must be converted manually. See https://docs.traefik.io/middlewares/retry/")
	}

	if oldCfg.Constraints != nil {
		fmt.Println("Global Constraints must be converted manually to provider constraints. See https://docs.traefik.io/providers/docker/#constraints")
	}

	if oldCfg.Web != nil {
		fmt.Println("Web must be converted manually. See https://docs.traefik.io/operations/api/")
	}

	return static.Configuration{
		Global: &static.Global{
			CheckNewVersion:    oldCfg.CheckNewVersion,
			SendAnonymousUsage: oldCfg.SendAnonymousUsage,
		},
		ServersTransport:      migrateServersTransport(oldCfg),
		EntryPoints:           migrateEntryPoints(oldCfg),
		Providers:             migrateProviders(oldCfg),
		API:                   migrateAPI(oldCfg),
		Metrics:               migrateMetrics(oldCfg),
		Ping:                  migratePing(oldCfg),
		Log:                   migrateTraefikLog(oldCfg),
		AccessLog:             migrateAccessLog(oldCfg),
		Tracing:               migrateTracing(oldCfg),
		HostResolver:          migrateHostResolver(oldCfg),
		CertificatesResolvers: migrateACME(oldCfg),
	}
}

func migratePing(oldCfg Configuration) *ping.Handler {
	if oldCfg.Ping == nil {
		return nil
	}

	return &ping.Handler{
		EntryPoint: oldCfg.Ping.EntryPoint,
	}
}

func migrateAPI(oldCfg Configuration) *static.API {
	if oldCfg.API == nil {
		return nil
	}

	if oldCfg.API.EntryPoint != "" {
		fmt.Printf("The entry point (%s) defined in API must be converted manually. See https://docs.traefik.io/operations/api/\n", oldCfg.API.EntryPoint)
	}

	return &static.API{
		Insecure:  true,
		Dashboard: oldCfg.API.Dashboard,
		Debug:     oldCfg.API.Debug,
	}
}

func migrateEntryPoints(oldCfg Configuration) static.EntryPoints {
	if oldCfg.EntryPoints == nil {
		return nil
	}

	eps := static.EntryPoints{}
	for name, entryPoint := range *oldCfg.EntryPoints {
		if entryPoint.Compress {
			fmt.Printf("Compress on entry point %q must be converted manually. See https://docs.traefik.io/middlewares/compress/\n", name)
		}
		if entryPoint.TLS != nil {
			fmt.Printf("TLS on entry point %q must be converted manually. See https://docs.traefik.io/routing/routers/#tls\n", name)
		}
		if entryPoint.Redirect != nil {
			fmt.Printf("Redirect on entry point %q must be converted manually. See https://docs.traefik.io/middlewares/redirectscheme/\n", name)
		}
		if entryPoint.WhiteList != nil {
			fmt.Printf("WhiteList on entry point %q must be converted manually. See https://docs.traefik.io/middlewares/ipwhitelist/\n", name)
		}
		if len(entryPoint.WhitelistSourceRange) != 0 {
			fmt.Printf("WhitelistSourceRange on entry point %q must be converted manually. See https://docs.traefik.io/middlewares/ipwhitelist/\n", name)
		}

		eps[name] = &static.EntryPoint{
			Address:          entryPoint.Address,
			Transport:        migrateEntryPointsTransport(oldCfg),
			ProxyProtocol:    migrateProxyProtocol(entryPoint),
			ForwardedHeaders: migrateEntryPointForwardedHeaders(entryPoint),
		}
	}
	return eps
}

func migrateEntryPointsTransport(oldCfg Configuration) *static.EntryPointsTransport {
	if oldCfg.LifeCycle == nil || oldCfg.RespondingTimeouts == nil {
		return nil
	}

	return &static.EntryPointsTransport{
		LifeCycle:          migrateLifeCycle(oldCfg),
		RespondingTimeouts: migrateRespondingTimeouts(oldCfg),
	}
}

func migrateHostResolver(oldCfg Configuration) *types.HostResolverConfig {
	if oldCfg.HostResolver == nil {
		return nil
	}

	// TODO SKIP ?
	return &types.HostResolverConfig{
		CnameFlattening: oldCfg.HostResolver.CnameFlattening,
		ResolvConfig:    oldCfg.HostResolver.ResolvConfig,
		ResolvDepth:     oldCfg.HostResolver.ResolvDepth,
	}
}

func migrateRespondingTimeouts(oldCfg Configuration) *static.RespondingTimeouts {
	if oldCfg.RespondingTimeouts == nil {
		return nil
	}

	return &static.RespondingTimeouts{
		ReadTimeout:  convertDuration(oldCfg.RespondingTimeouts.ReadTimeout, 0),
		WriteTimeout: convertDuration(oldCfg.RespondingTimeouts.WriteTimeout, 0),
		IdleTimeout:  convertDuration(oldCfg.RespondingTimeouts.IdleTimeout, 180*time.Second),
	}
}

func migrateLifeCycle(oldCfg Configuration) *static.LifeCycle {
	if oldCfg.LifeCycle == nil {
		return nil
	}

	return &static.LifeCycle{
		RequestAcceptGraceTimeout: convertDuration(oldCfg.LifeCycle.RequestAcceptGraceTimeout, 0),
		GraceTimeOut:              convertDuration(oldCfg.LifeCycle.GraceTimeOut, 10*time.Second),
	}
}

func migrateEntryPointForwardedHeaders(entryPoint EntryPoint) *static.ForwardedHeaders {
	if entryPoint.ForwardedHeaders == nil {
		return nil
	}

	return &static.ForwardedHeaders{
		Insecure:   entryPoint.ForwardedHeaders.Insecure,
		TrustedIPs: entryPoint.ForwardedHeaders.TrustedIPs,
	}
}

func migrateProxyProtocol(entryPoint EntryPoint) *static.ProxyProtocol {
	if entryPoint.ProxyProtocol == nil {
		return nil
	}

	return &static.ProxyProtocol{
		Insecure:   entryPoint.ProxyProtocol.Insecure,
		TrustedIPs: entryPoint.ProxyProtocol.TrustedIPs,
	}
}

func migrateServersTransport(oldCfg Configuration) *static.ServersTransport {
	var serversTransport *static.ServersTransport
	if oldCfg.InsecureSkipVerify || oldCfg.MaxIdleConnsPerHost > 0 {
		serversTransport = &static.ServersTransport{
			InsecureSkipVerify:  oldCfg.InsecureSkipVerify,
			MaxIdleConnsPerHost: oldCfg.MaxIdleConnsPerHost,
		}
	}

	if len(oldCfg.RootCAs) > 0 {
		if serversTransport == nil {
			serversTransport = &static.ServersTransport{}
		}

		var rootCas []tls.FileOrContent
		for _, ca := range oldCfg.RootCAs {
			rootCas = append(rootCas, tls.FileOrContent(ca))
		}
		serversTransport.RootCAs = rootCas
	}

	if oldCfg.ForwardingTimeouts != nil {
		if serversTransport == nil {
			serversTransport = &static.ServersTransport{}
		}

		timeouts := &static.ForwardingTimeouts{
			DialTimeout:           convertDuration(oldCfg.ForwardingTimeouts.DialTimeout, 30*time.Second),
			ResponseHeaderTimeout: convertDuration(oldCfg.ForwardingTimeouts.ResponseHeaderTimeout, 0),
			IdleConnTimeout:       convertDuration(oldCfg.IdleTimeout, 180*time.Second),
		}

		serversTransport.ForwardingTimeouts = timeouts
	}

	return serversTransport
}

func convertDuration(value parse.Duration, defaultDuration time.Duration) types.Duration {
	if value == 0 {
		return types.Duration(defaultDuration)
	}

	return types.Duration(value)
}

package static

import (
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/containous/flaeg/parse"
	"github.com/containous/traefik/v2/pkg/config/static"
	"github.com/containous/traefik/v2/pkg/ping"
	"github.com/containous/traefik/v2/pkg/provider/acme"
	"github.com/containous/traefik/v2/pkg/provider/docker"
	"github.com/containous/traefik/v2/pkg/provider/file"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/ingress"
	"github.com/containous/traefik/v2/pkg/provider/marathon"
	"github.com/containous/traefik/v2/pkg/provider/rancher"
	"github.com/containous/traefik/v2/pkg/provider/rest"
	"github.com/containous/traefik/v2/pkg/tls"
	"github.com/containous/traefik/v2/pkg/tracing/datadog"
	"github.com/containous/traefik/v2/pkg/tracing/jaeger"
	"github.com/containous/traefik/v2/pkg/tracing/zipkin"
	"github.com/containous/traefik/v2/pkg/types"
	"gopkg.in/yaml.v2"
)

// Convert old static configuration file to the Traefik v2 static configuration files.
func Convert(oldFilename string, outputDir string) error {
	err := os.MkdirAll(outputDir, 0755)
	if err != nil {
		return err
	}

	oldCfg := Configuration{}

	_, err = toml.DecodeFile(oldFilename, &oldCfg)
	if err != nil {
		return err
	}

	newCfg := migrateConfiguration(oldCfg)

	err = writeFile(filepath.Join(outputDir, "new-traefik.yml"), func(w io.Writer) encoder {
		return yaml.NewEncoder(w)
	}, newCfg)
	if err != nil {
		return err
	}

	err = writeFile(filepath.Join(outputDir, "new-traefik.toml"), func(w io.Writer) encoder {
		return toml.NewEncoder(w)
	}, newCfg)
	if err != nil {
		return err
	}

	return nil
}

type encoder interface {
	Encode(v interface{}) error
}

func writeFile(filename string, enc func(w io.Writer) encoder, newCfg static.Configuration) error {
	cfgFile, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer func() { _ = cfgFile.Close() }()

	return enc(cfgFile).Encode(newCfg)
}

func migrateConfiguration(oldCfg Configuration) static.Configuration {
	return static.Configuration{
		Global: &static.Global{
			CheckNewVersion:    true,
			SendAnonymousUsage: true,
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

func migrateProviders(oldCfg Configuration) *static.Providers {
	if oldCfg.ECS != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ECS), "*static."))
	}
	if oldCfg.Consul != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Consul), "*static."))
	}
	if oldCfg.ConsulCatalog != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ConsulCatalog), "*static."))
	}
	if oldCfg.Etcd != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Etcd), "*static."))
	}
	if oldCfg.Zookeeper != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Zookeeper), "*static."))
	}
	if oldCfg.Boltdb != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Boltdb), "*static."))
	}
	if oldCfg.Mesos != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Mesos), "*static."))
	}
	if oldCfg.Eureka != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Eureka), "*static."))
	}
	if oldCfg.DynamoDB != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.DynamoDB), "*static."))
	}
	if oldCfg.ServiceFabric != nil {
		fmt.Printf("The provider %s is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ServiceFabric), "*static."))
	}

	return &static.Providers{
		ProvidersThrottleDuration: convertDuration(oldCfg.ProvidersThrottleDuration, 2*time.Second),
		Docker:                    migrateDocker(oldCfg),
		File:                      migrateFile(oldCfg),
		Marathon:                  migrateMarathon(oldCfg),
		KubernetesIngress:         migrateKubernetes(oldCfg),
		KubernetesCRD:             nil, // SKIP
		Rest:                      migrateRest(oldCfg),
		Rancher:                   migrateRancher(oldCfg),
	}
}

func migrateACME(oldCfg Configuration) map[string]static.CertificateResolver {
	if oldCfg.ACME == nil {
		return nil
	}

	acmeCfg := &acme.Configuration{
		Email:         oldCfg.ACME.Email,
		CAServer:      oldCfg.ACME.CAServer,
		Storage:       oldCfg.ACME.Storage,
		KeyType:       oldCfg.ACME.KeyType,
		DNSChallenge:  migrateDNSChallenge(oldCfg),
		HTTPChallenge: migrateHTTPChallenge(oldCfg),
	}

	if oldCfg.ACME.TLSChallenge != nil {
		acmeCfg.TLSChallenge = &acme.TLSChallenge{}
	}

	return map[string]static.CertificateResolver{
		"default": {ACME: acmeCfg},
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

func migrateTracing(oldCfg Configuration) *static.Tracing {
	if oldCfg.Tracing == nil {
		return nil
	}

	return &static.Tracing{
		ServiceName:   oldCfg.Tracing.ServiceName,
		SpanNameLimit: oldCfg.Tracing.SpanNameLimit,
		Jaeger:        migrateJaeger(oldCfg),
		Zipkin:        migrateZipkin(oldCfg),
		Datadog:       migrateDatadogTracing(oldCfg),
		Instana:       nil, // SKIP
		Haystack:      nil, // SKIP
	}
}

func migrateJaeger(oldCfg Configuration) *jaeger.Config {
	if oldCfg.Tracing.Jaeger == nil {
		return nil
	}

	return &jaeger.Config{
		SamplingServerURL:      oldCfg.Tracing.Jaeger.SamplingServerURL,
		SamplingType:           oldCfg.Tracing.Jaeger.SamplingType,
		SamplingParam:          oldCfg.Tracing.Jaeger.SamplingParam,
		LocalAgentHostPort:     oldCfg.Tracing.Jaeger.LocalAgentHostPort,
		Gen128Bit:              false, // SKIP
		Propagation:            "",    // SKIP
		TraceContextHeaderName: oldCfg.Tracing.Jaeger.TraceContextHeaderName,
		Collector:              nil, // SKIP
	}
}

func migrateZipkin(oldCfg Configuration) *zipkin.Config {
	if oldCfg.Tracing.Zipkin == nil {
		return nil
	}

	return &zipkin.Config{
		HTTPEndpoint: oldCfg.Tracing.Zipkin.HTTPEndpoint,
		SameSpan:     oldCfg.Tracing.Zipkin.SameSpan,
		ID128Bit:     oldCfg.Tracing.Zipkin.ID128Bit,
		SampleRate:   0, // SKIP
	}
}

func migrateDatadogTracing(oldCfg Configuration) *datadog.Config {
	if oldCfg.Tracing.DataDog == nil {
		return nil
	}

	return &datadog.Config{
		LocalAgentHostPort:         oldCfg.Tracing.DataDog.LocalAgentHostPort,
		GlobalTag:                  oldCfg.Tracing.DataDog.GlobalTag,
		Debug:                      oldCfg.Tracing.DataDog.Debug,
		PrioritySampling:           oldCfg.Tracing.DataDog.PrioritySampling,
		TraceIDHeaderName:          oldCfg.Tracing.DataDog.TraceIDHeaderName,
		ParentIDHeaderName:         oldCfg.Tracing.DataDog.ParentIDHeaderName,
		SamplingPriorityHeaderName: oldCfg.Tracing.DataDog.SamplingPriorityHeaderName,
		BagagePrefixHeaderName:     oldCfg.Tracing.DataDog.BagagePrefixHeaderName,
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

func migrateMetrics(oldCfg Configuration) *types.Metrics {
	if oldCfg.Metrics == nil {
		return nil
	}

	return &types.Metrics{
		Prometheus: migratePrometheus(oldCfg),
		Datadog:    migrateDatadog(oldCfg),
		StatsD:     migrateStatsD(oldCfg),
		InfluxDB:   migrateInfluxDB(oldCfg),
	}
}

func migrateInfluxDB(oldCfg Configuration) *types.InfluxDB {
	if oldCfg.Metrics.InfluxDB == nil {
		return nil
	}

	return &types.InfluxDB{
		Address:              oldCfg.Metrics.InfluxDB.Address,
		Protocol:             oldCfg.Metrics.InfluxDB.Protocol,
		PushInterval:         parsePushInterval(oldCfg.Metrics.InfluxDB.PushInterval),
		Database:             oldCfg.Metrics.InfluxDB.Database,
		RetentionPolicy:      oldCfg.Metrics.InfluxDB.RetentionPolicy,
		Username:             "",
		Password:             "",
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migrateStatsD(oldCfg Configuration) *types.Statsd {
	if oldCfg.Metrics.StatsD == nil {
		return nil
	}

	return &types.Statsd{
		Address:              oldCfg.Metrics.StatsD.Address,
		PushInterval:         parsePushInterval(oldCfg.Metrics.StatsD.PushInterval),
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migrateDatadog(oldCfg Configuration) *types.Datadog {
	if oldCfg.Metrics.Datadog == nil {
		return nil
	}

	return &types.Datadog{
		Address:              oldCfg.Metrics.Datadog.Address,
		PushInterval:         parsePushInterval(oldCfg.Metrics.Datadog.PushInterval),
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
	}
}

func migratePrometheus(oldCfg Configuration) *types.Prometheus {
	if oldCfg.Metrics.Prometheus == nil {
		return nil
	}

	return &types.Prometheus{
		Buckets:              oldCfg.Metrics.Prometheus.Buckets,
		AddEntryPointsLabels: false, // FIXME true ?
		AddServicesLabels:    false, // FIXME true ?
		EntryPoint:           oldCfg.Metrics.Prometheus.EntryPoint,
	}
}

func migrateRancher(oldCfg Configuration) *rancher.Provider {
	if oldCfg.Rancher == nil {
		return nil
	}

	if len(oldCfg.Rancher.Constraints) != 0 {
		fmt.Println("The constraints on the Rancher must be converted manually. https://docs.traefik.io/v2.0/providers/rancher/#constraints")
	}

	rancherCfg := &rancher.Provider{
		Constraints:               "", // SKIP
		Watch:                     oldCfg.Rancher.Watch,
		DefaultRule:               "", // SKIP
		ExposedByDefault:          oldCfg.Rancher.ExposedByDefault,
		EnableServiceHealthFilter: oldCfg.Rancher.EnableServiceHealthFilter,
		RefreshSeconds:            oldCfg.Rancher.RefreshSeconds,
	}

	if oldCfg.Rancher.Metadata != nil {
		rancherCfg.IntervalPoll = oldCfg.Rancher.Metadata.IntervalPoll
		rancherCfg.Prefix = oldCfg.Rancher.Metadata.Prefix
	}

	return rancherCfg
}

func migrateKubernetes(oldCfg Configuration) *ingress.Provider {
	if oldCfg.Kubernetes == nil {
		return nil
	}

	return &ingress.Provider{
		Endpoint:               oldCfg.Kubernetes.Endpoint,
		Token:                  oldCfg.Kubernetes.Token,
		CertAuthFilePath:       oldCfg.Kubernetes.CertAuthFilePath,
		DisablePassHostHeaders: oldCfg.Kubernetes.DisablePassHostHeaders,
		Namespaces:             oldCfg.Kubernetes.Namespaces,
		LabelSelector:          oldCfg.Kubernetes.LabelSelector,
		IngressClass:           oldCfg.Kubernetes.IngressClass,
		ThrottleDuration:       convertDuration(oldCfg.Kubernetes.ThrottleDuration, 0),
		IngressEndpoint:        migrateIngressEndpoint(oldCfg),
	}
}

func migrateIngressEndpoint(oldCfg Configuration) *ingress.EndpointIngress {
	if oldCfg.Kubernetes.IngressEndpoint == nil {
		return nil
	}

	return &ingress.EndpointIngress{
		IP:               oldCfg.Kubernetes.IngressEndpoint.IP,
		Hostname:         oldCfg.Kubernetes.IngressEndpoint.Hostname,
		PublishedService: oldCfg.Kubernetes.IngressEndpoint.PublishedService,
	}
}

func migrateMarathon(oldCfg Configuration) *marathon.Provider {
	if oldCfg.Marathon == nil {
		return nil
	}

	if len(oldCfg.Marathon.Constraints) != 0 {
		fmt.Println("The constraints on the Marathon must be converted manually. https://docs.traefik.io/v2.0/providers/marathon/#constraints")
	}

	if len(oldCfg.Marathon.Domain) != 0 {
		fmt.Println("The domain has been removed from Marathon, instead use https://docs.traefik.io/v2.0/providers/marathon/#defaultrule")
	}

	return &marathon.Provider{
		Constraints:            "", // TODO SKIP ?
		Trace:                  oldCfg.Marathon.Trace,
		Watch:                  oldCfg.Marathon.Watch,
		Endpoint:               oldCfg.Marathon.Endpoint,
		DefaultRule:            "", // TODO SKIP ?
		ExposedByDefault:       oldCfg.Marathon.ExposedByDefault,
		DCOSToken:              oldCfg.Marathon.DCOSToken,
		TLS:                    migrateClientTLS(oldCfg.Marathon.TLS),
		DialerTimeout:          convertDuration(oldCfg.Marathon.DialerTimeout, 5*time.Second),
		ResponseHeaderTimeout:  convertDuration(oldCfg.Marathon.ResponseHeaderTimeout, 60*time.Second),
		TLSHandshakeTimeout:    convertDuration(oldCfg.Marathon.TLSHandshakeTimeout, 5*time.Second),
		KeepAlive:              convertDuration(oldCfg.Marathon.KeepAlive, 10*time.Second),
		ForceTaskHostname:      oldCfg.Marathon.ForceTaskHostname,
		RespectReadinessChecks: oldCfg.Marathon.RespectReadinessChecks,
		Basic:                  migrateMarathonBasic(oldCfg),
	}
}

func migrateMarathonBasic(oldCfg Configuration) *marathon.Basic {
	if oldCfg.Marathon.Basic == nil {
		return nil
	}

	return &marathon.Basic{
		HTTPBasicAuthUser: oldCfg.Marathon.Basic.HTTPBasicAuthUser,
		HTTPBasicPassword: oldCfg.Marathon.Basic.HTTPBasicPassword,
	}
}

func migrateFile(oldCfg Configuration) *file.Provider {
	if oldCfg.File == nil {
		return nil
	}

	return &file.Provider{
		Directory:                 oldCfg.File.Directory,
		Watch:                     oldCfg.File.Watch,
		Filename:                  oldCfg.File.Filename,
		DebugLogGeneratedTemplate: oldCfg.File.DebugLogGeneratedTemplate,
	}
}

func migrateDocker(oldCfg Configuration) *docker.Provider {
	if oldCfg.Docker == nil {
		return nil
	}

	if len(oldCfg.Docker.Constraints) != 0 {
		fmt.Println("The constraints on the Docker must be converted manually. https://docs.traefik.io/v2.0/providers/docker/#constraints")
	}

	if len(oldCfg.Docker.Domain) != 0 {
		fmt.Println("The domain has been removed from Docker, instead use https://docs.traefik.io/v2.0/providers/docker/#defaultrule")
	}

	swarmModeRefreshSeconds := types.Duration(15 * time.Second)
	if oldCfg.Docker.SwarmModeRefreshSeconds > 0 {
		swarmModeRefreshSeconds = types.Duration(time.Duration(oldCfg.Docker.SwarmModeRefreshSeconds) * time.Second)
	}

	return &docker.Provider{
		Constraints:             "", // TODO SKIP ?
		Watch:                   oldCfg.Docker.Watch,
		Endpoint:                oldCfg.Docker.Endpoint,
		DefaultRule:             "", // TODO SKIP ?
		TLS:                     migrateClientTLS(oldCfg.Docker.TLS),
		ExposedByDefault:        oldCfg.Docker.ExposedByDefault,
		UseBindPortIP:           oldCfg.Docker.UseBindPortIP,
		SwarmMode:               oldCfg.Docker.SwarmMode,
		Network:                 oldCfg.Docker.Network,
		SwarmModeRefreshSeconds: swarmModeRefreshSeconds,
	}
}

func migrateRest(oldCfg Configuration) *rest.Provider {
	if oldCfg.Rest == nil {
		return nil
	}

	if oldCfg.Rest.EntryPoint != "" {
		fmt.Printf("The entry point on REST provider cannot be set [%s], instead use https://docs.traefik.io/v2.0/operations/api/\n", oldCfg.Rest.EntryPoint)
	}
	return &rest.Provider{
		Insecure: true,
	}
}

func migrateClientTLS(oldClientTLS *ClientTLS) *types.ClientTLS {
	if oldClientTLS == nil {
		return nil
	}

	return &types.ClientTLS{
		CA:                 oldClientTLS.Ca,
		CAOptional:         oldClientTLS.CaOptional,
		Cert:               oldClientTLS.Cert,
		Key:                oldClientTLS.Key,
		InsecureSkipVerify: oldClientTLS.InsecureSkipVerify,
	}
}

func migrateAccessLog(oldCfg Configuration) *types.AccessLog {
	if oldCfg.AccessLog == nil {
		return nil
	}

	return &types.AccessLog{
		FilePath:      oldCfg.AccessLog.File,
		Format:        oldCfg.AccessLog.Format,
		Filters:       migrateAccessLogFilters(oldCfg),
		Fields:        migrateAccessLogFields(oldCfg),
		BufferingSize: oldCfg.AccessLog.BufferingSize,
	}
}

func migrateAccessLogFields(oldCfg Configuration) *types.AccessLogFields {
	if oldCfg.AccessLog.Fields == nil {
		return nil
	}

	return &types.AccessLogFields{
		DefaultMode: oldCfg.AccessLog.Fields.DefaultMode,
		Names:       oldCfg.AccessLog.Fields.Names,
		Headers:     migrateFieldHeaders(oldCfg),
	}
}

func migrateFieldHeaders(oldCfg Configuration) *types.FieldHeaders {
	if oldCfg.AccessLog.Fields.Headers == nil {
		return nil
	}

	return &types.FieldHeaders{
		DefaultMode: oldCfg.AccessLog.Fields.Headers.DefaultMode,
		Names:       oldCfg.AccessLog.Fields.Headers.Names,
	}
}

func migrateAccessLogFilters(oldCfg Configuration) *types.AccessLogFilters {
	if oldCfg.AccessLog.Filters == nil {
		return nil
	}

	return &types.AccessLogFilters{
		StatusCodes:   oldCfg.AccessLog.Filters.StatusCodes,
		RetryAttempts: oldCfg.AccessLog.Filters.RetryAttempts,
		MinDuration:   convertDuration(oldCfg.AccessLog.Filters.Duration, 0),
	}
}

func migrateTraefikLog(oldCfg Configuration) *types.TraefikLog {
	logCfg := &types.TraefikLog{
		Level: oldCfg.LogLevel,
	}

	if oldCfg.TraefikLog != nil {
		logCfg.FilePath = oldCfg.TraefikLog.File
		logCfg.Format = oldCfg.TraefikLog.Format
	}
	return logCfg
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
		fmt.Printf("The entry point on API cannot be set [%s], instead use https://docs.traefik.io/v2.0/operations/api/\n", oldCfg.API.EntryPoint)
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
			fmt.Printf("Compress on entry point [%s] is not supported by Traefik v2, instead use https://docs.traefik.io/v2.0/middlewares/compress/\n", name)
		}
		if entryPoint.TLS != nil {
			fmt.Printf("TLS on entry point [%s] is not supported by Traefik v2, instead use https://docs.traefik.io/v2.0/routing/routers/#tls\n", name)
		}
		if entryPoint.Redirect != nil {
			fmt.Printf("Redirect on entry point [%s] is not supported by Traefik v2, instead use https://docs.traefik.io/v2.0/middlewares/redirectscheme/\n", name)
		}
		if entryPoint.WhiteList != nil {
			fmt.Printf("WhiteList on entry point [%s] is not supported by Traefik v2, instead use https://docs.traefik.io/v2.0/middlewares/ipwhitelist/\n", name)
		}
		if len(entryPoint.WhitelistSourceRange) != 0 {
			fmt.Printf("WhiteList on entry point [%s] is not supported by Traefik v2, instead use https://docs.traefik.io/v2.0/middlewares/ipwhitelist/\n", name)
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
		var rootCas []tls.FileOrContent
		for _, ca := range oldCfg.RootCAs {
			rootCas = append(rootCas, tls.FileOrContent(ca))
		}

		serversTransport = &static.ServersTransport{
			InsecureSkipVerify:  oldCfg.InsecureSkipVerify,
			RootCAs:             rootCas,
			MaxIdleConnsPerHost: oldCfg.MaxIdleConnsPerHost,
		}
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

func parsePushInterval(value string) types.Duration {
	if value == "" {
		return types.Duration(10 * time.Second)
	}

	pushInternal, err := time.ParseDuration(value)
	if err != nil {
		log.Fatal(err)
	}

	return types.Duration(pushInternal)
}

func convertDuration(value parse.Duration, defaultDuration time.Duration) types.Duration {
	if value == 0 {
		return types.Duration(defaultDuration)
	}

	return types.Duration(value)
}

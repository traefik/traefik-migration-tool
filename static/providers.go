package static

import (
	"fmt"
	"strings"
	"time"

	"github.com/traefik/traefik/v2/pkg/config/static"
	"github.com/traefik/traefik/v2/pkg/provider/docker"
	"github.com/traefik/traefik/v2/pkg/provider/file"
	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/ingress"
	"github.com/traefik/traefik/v2/pkg/provider/marathon"
	"github.com/traefik/traefik/v2/pkg/provider/rancher"
	"github.com/traefik/traefik/v2/pkg/provider/rest"
	"github.com/traefik/traefik/v2/pkg/types"
)

func migrateProviders(oldCfg Configuration) *static.Providers {
	if oldCfg.ECS != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ECS), "*static."))
	}
	if oldCfg.Consul != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Consul), "*static."))
	}
	if oldCfg.ConsulCatalog != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ConsulCatalog), "*static."))
	}
	if oldCfg.Etcd != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Etcd), "*static."))
	}
	if oldCfg.Zookeeper != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Zookeeper), "*static."))
	}
	if oldCfg.Boltdb != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Boltdb), "*static."))
	}
	if oldCfg.Mesos != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Mesos), "*static."))
	}
	if oldCfg.Eureka != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.Eureka), "*static."))
	}
	if oldCfg.DynamoDB != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.DynamoDB), "*static."))
	}
	if oldCfg.ServiceFabric != nil {
		fmt.Printf("The %s provider is currently not supported by Traefik v2.\n", strings.TrimPrefix(fmt.Sprintf("%T", oldCfg.ServiceFabric), "*static."))
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

func migrateRancher(oldCfg Configuration) *rancher.Provider {
	if oldCfg.Rancher == nil {
		return nil
	}

	if len(oldCfg.Rancher.Constraints) != 0 {
		fmt.Println("The constraints on the Rancher provider must be converted manually. https://docs.traefik.io/providers/rancher/#constraints")
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
		fmt.Println("The constraints on the Marathon provider must be converted manually. https://docs.traefik.io/providers/marathon/#constraints")
	}

	if len(oldCfg.Marathon.Domain) != 0 {
		fmt.Printf("The domain (%s) defined the Marathon provider must be converted manually. See https://docs.traefik.io/providers/marathon/#defaultrule\n", oldCfg.Marathon.Domain)
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

	if oldCfg.File.Directory == "" && oldCfg.File.Filename == "" {
		fmt.Println("All the elements related to dynamic configuration (backends, frontends, ...) must be converted manually. See https://docs.traefik.io/routing/overview/")
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
		fmt.Println("The constraints defined in the Docker provider must be converted manually. See https://docs.traefik.io/providers/docker/#constraints")
	}

	if len(oldCfg.Docker.Domain) != 0 {
		fmt.Printf("The domain (%s) defined in the Docker provider must be converted manually. See https://docs.traefik.io/providers/docker/#defaultrule\n", oldCfg.Docker.Domain)
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
		fmt.Printf("The entry point (%s) defined in the REST provider must be converted manually. See https://docs.traefik.io/operations/api/\n", oldCfg.Rest.EntryPoint)
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

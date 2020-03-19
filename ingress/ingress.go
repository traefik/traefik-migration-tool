// Package ingress convert Ingress to IngressRoute
package ingress

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	extensions "k8s.io/api/extensions/v1beta1"
	networking "k8s.io/api/networking/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/yaml"
)

const separator = "---"

const groupSuffix = "/v1alpha1"

const (
	ruleTypePath             = "Path"
	ruleTypePathPrefix       = "PathPrefix"
	ruleTypePathStrip        = "PathStrip"
	ruleTypePathPrefixStrip  = "PathPrefixStrip"
	ruleTypeAddPrefix        = "AddPrefix"
	ruleTypeReplacePath      = "ReplacePath"
	ruleTypeReplacePathRegex = "ReplacePathRegex"
)

// ServiceKey is used to uniquely identify a service when grouping routes
type ServiceKey struct {
	v1alpha1.LoadBalancerSpec
	MiRefKey string
}

// ServiceRule defines a host and path rule pair, derived from IngressRule
type ServiceRule struct {
	Host string
	Path string
}

// Convert converts all ingress in a src into a dstDir
func Convert(src, dstDir string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		filename := info.Name()
		srcPath := filepath.Dir(src)
		return convertFile(srcPath, dstDir, filename)
	}

	dir := info.Name()
	infos, err := ioutil.ReadDir(src)
	if err != nil {
		return err
	}

	for _, info := range infos {
		newSrc := filepath.Join(src, info.Name())
		newDst := filepath.Join(dstDir, dir)
		err := Convert(newSrc, newDst)
		if err != nil {
			return err
		}
	}
	return nil
}

func convertFile(srcDir, dstDir, filename string) error {
	content, err := expandFileContent(filepath.Join(srcDir, filename))
	if err != nil {
		return err
	}

	err = os.MkdirAll(dstDir, 0755)
	if err != nil {
		return err
	}

	parts := strings.Split(string(content), separator)
	var fragments []string
	for _, part := range parts {
		if part == "\n" || part == "" {
			continue
		}

		unstruct, err := createUnstructured([]byte(part))
		if err != nil {
			return err
		}

		if unstruct.IsList() {
			fragments = append(fragments, part)
			continue
		}

		object, err := parseYaml([]byte(part))
		if err != nil {
			log.Printf("err while reading yaml: %v", err)
			fragments = append(fragments, part)
			continue
		}

		var ingress *networking.Ingress
		switch obj := object.(type) {
		case *extensions.Ingress:
			ingress, err = extensionsToNetworking(obj)
			if err != nil {
				return err
			}
		case *networking.Ingress:
			ingress = obj
		default:
			log.Printf("the object is skipped because is not an Ingress: %T", object)
			fragments = append(fragments, part)
			continue
		}

		objects := convertIngress(ingress)
		for _, object := range objects {
			yml, err := encodeYaml(object, v1alpha1.GroupName+groupSuffix)
			if err != nil {
				return err
			}
			fragments = append(fragments, yml)
		}
	}

	return ioutil.WriteFile(filepath.Join(dstDir, filename), []byte(strings.Join(fragments, separator+"\n")), 0666)
}

func expandFileContent(filePath string) ([]byte, error) {
	content, err := ioutil.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	parts := strings.Split(string(content), separator)
	var fragments []string
	for _, part := range parts {
		if part == "\n" || part == "" {
			continue
		}

		listObj, err := createUnstructured(content)
		if err != nil {
			return nil, err
		}

		if !listObj.IsList() {
			fragments = append(fragments, part)
			continue
		}

		items, _, err := unstructured.NestedSlice(listObj.Object, "items")
		if err != nil {
			return nil, err
		}

		toKeep, toConvert := extractItems(items)

		if len(items) == len(toKeep) {
			fragments = append(fragments, part)
			continue
		}

		if len(toKeep) > 0 {
			newObj := listObj.DeepCopy()

			err = unstructured.SetNestedSlice(newObj.Object, toKeep, "items")
			if err != nil {
				return nil, err
			}

			m, err := yaml.Marshal(newObj)
			if err != nil {
				return nil, err
			}

			fragments = append(fragments, string(m))
		}

		for _, elt := range toConvert {
			m, err := yaml.Marshal(elt.Object)
			if err != nil {
				return nil, err
			}
			fragments = append(fragments, string(m))
		}
	}

	return []byte(strings.Join(fragments, separator+"\n")), nil
}

func createUnstructured(content []byte) (*unstructured.Unstructured, error) {
	listObj := &unstructured.Unstructured{Object: map[string]interface{}{}}

	if err := yaml.Unmarshal(content, &listObj.Object); err != nil {
		return nil, fmt.Errorf("error decoding YAML: %w\noriginal YAML: %s", err, string(content))
	}

	return listObj, nil
}

func extractItems(items []interface{}) ([]interface{}, []unstructured.Unstructured) {
	var toKeep []interface{}
	var toConvert []unstructured.Unstructured

	for _, elt := range items {
		obj := unstructured.Unstructured{Object: elt.(map[string]interface{})}
		if (obj.GetAPIVersion() == "extensions/v1beta1" || obj.GetAPIVersion() == "networking.k8s.io/v1beta1") && obj.GetKind() == "Ingress" {
			toConvert = append(toConvert, obj)
		} else {
			toKeep = append(toKeep, elt)
		}
	}

	return toKeep, toConvert
}

// convertIngress converts an *networking.Ingress to a slice of runtime.Object (IngressRoute and Middlewares)
func convertIngress(ingress *networking.Ingress) []runtime.Object {
	logUnsupported(ingress)

	ingressRoute := &v1alpha1.IngressRoute{
		ObjectMeta: v1.ObjectMeta{Name: ingress.GetName(), Namespace: ingress.GetNamespace(), Annotations: map[string]string{}},
		Spec: v1alpha1.IngressRouteSpec{
			EntryPoints: getSliceStringValue(ingress.GetAnnotations(), annotationKubernetesFrontendEntryPoints),
		},
	}

	ingressClass := getStringValue(ingress.GetAnnotations(), annotationKubernetesIngressClass, "")
	if len(ingressClass) > 0 {
		ingressRoute.GetAnnotations()[annotationKubernetesIngressClass] = ingressClass
	}

	var middlewares []*v1alpha1.Middleware

	// Headers middleware
	headers := getHeadersMiddleware(ingress)
	if headers != nil {
		middlewares = append(middlewares, headers)
	}

	// Auth middleware
	auth := getAuthMiddleware(ingress)
	if auth != nil {
		middlewares = append(middlewares, auth)
	}

	// Whitelist middleware
	whiteList := getWhiteList(ingress)
	if whiteList != nil {
		middlewares = append(middlewares, whiteList)
	}

	// PassTLSCert middleware
	passTLSCert := getPassTLSClientCert(ingress)
	if passTLSCert != nil {
		middlewares = append(middlewares, passTLSCert)
	}

	// rateLimit middleware
	middlewares = append(middlewares, getRateLimit(ingress)...)

	requestModifier := getStringValue(ingress.GetAnnotations(), annotationKubernetesRequestModifier, "")
	if requestModifier != "" {
		middleware, err := parseRequestModifier(ingress.GetNamespace(), requestModifier)
		if err != nil {
			log.Printf("Invalid %s: %v", annotationKubernetesRequestModifier, err)
		}

		middlewares = append(middlewares, middleware)
	}

	var miRefs []v1alpha1.MiddlewareRef
	for _, mi := range middlewares {
		miRefs = append(miRefs, toRef(mi))
	}

	routes, mi, err := createRoutes(ingress.GetNamespace(), ingress.Spec.Rules, ingress.GetAnnotations(), miRefs)
	if err != nil {
		log.Println(err)
		return nil
	}
	var routeVals []v1alpha1.Route
	for _, routePtr := range routes {
		routeVals = append(routeVals, *routePtr)
	}
	ingressRoute.Spec.Routes = routeVals

	middlewares = append(middlewares, mi...)

	sort.Slice(middlewares, func(i, j int) bool { return middlewares[i].Name < middlewares[j].Name })

	objects := []runtime.Object{ingressRoute}
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return objects
}

func createRoutes(namespace string, rules []networking.IngressRule, annotations map[string]string, middlewareRefs []v1alpha1.MiddlewareRef) ([]*v1alpha1.Route, []*v1alpha1.Middleware, error) {
	ruleType, stripPrefix, err := extractRuleType(annotations)
	if err != nil {
		return nil, nil, err
	}

	var mis []*v1alpha1.Middleware
	var services = map[ServiceKey][]ServiceRule{}
	var miRefsPerService = map[ServiceKey][]v1alpha1.MiddlewareRef{}

	for _, rule := range rules {
		for _, path := range rule.HTTP.Paths {
			var miRefs = make([]v1alpha1.MiddlewareRef, 0, 1)
			miRefs = append(miRefs, middlewareRefs...)

			if len(path.Path) > 0 {

				if stripPrefix {
					mi := getStripPrefix(path, rule.Host+path.Path, namespace)
					mis = append(mis, mi)
					miRefs = append(miRefs, toRef(mi))
				}

				rewriteTarget := getStringValue(annotations, annotationKubernetesRewriteTarget, "")
				if rewriteTarget != "" {
					if ruleType == ruleTypeReplacePath {
						return nil, nil, fmt.Errorf("rewrite-target must not be used together with annotation %q", annotationKubernetesRuleType)
					}

					mi := getReplacePathRegex(rule, path, namespace, rewriteTarget)
					mis = append(mis, mi)
					miRefs = append(miRefs, toRef(mi))
				}
			}

			redirect := getFrontendRedirect(namespace, annotations, rule.Host+path.Path, path.Path)
			if redirect != nil {
				mis = append(mis, redirect)
				miRefs = append(miRefs, toRef(redirect))
			}

			sort.Slice(miRefs, func(i, j int) bool { return miRefs[i].Name < miRefs[j].Name })

			serviceKey := ServiceKey{
				LoadBalancerSpec: v1alpha1.LoadBalancerSpec{
					Name:      path.Backend.ServiceName,
					Namespace: namespace,
					Kind:      "Service",
					Port:      path.Backend.ServicePort.IntVal,
					Scheme:    getStringValue(annotations, annotationKubernetesProtocol, ""),
				},
				MiRefKey: createMiddewareRefsKey(miRefs),
			}

			services[serviceKey] = append(services[serviceKey], ServiceRule{
				Host: rule.Host,
				Path: path.Path,
			})
			miRefsPerService[serviceKey] = miRefs
		}
	}

	routes := createRoutesPerService(services, ruleType, annotations, miRefsPerService)

	return routes, mis, nil
}

// creates routes by grouping them by service when possible
func createRoutesPerService(services map[ServiceKey][]ServiceRule, ruleType string, annotations map[string]string, miRefsPerService map[ServiceKey][]v1alpha1.MiddlewareRef) []*v1alpha1.Route {
	var routes []*v1alpha1.Route
	for serviceKey, serviceRules := range services {

		// group paths by host like this
		// H1 -> P1, P2
		// H2 -> P1, P2
		// H3 -> P3
		pathsPerHost := map[string][]string{}
		for _, serviceRule := range serviceRules {
			pathsPerHost[serviceRule.Host] = append(pathsPerHost[serviceRule.Host], serviceRule.Path)
		}

		// group hosts by paths, because host rules with the same set of paths can be merged together
		// "PathPrefix(P1, P2)" -> H1, H2
		// "PathPrefix(P3)" -> H3
		var hostsPerPathRule = map[string][]string{}
		for host, paths := range pathsPerHost {
			match := createMatchRule(paths, ruleType)
			hostsPerPathRule[match] = append(hostsPerPathRule[match], host)
		}

		// create host rules from hostsPerPathRule and copy the path rules
		// "Host(H1,H2)" -> "PathPrefix(P1, P2)"
		// "Host(H3)" -> "PathPrefix(P3)"
		resultingMatches := map[string]string{}
		for pathRule, hosts := range hostsPerPathRule {
			resultingMatches[createMatchRule(hosts, "Host")] = pathRule
		}

		routes = append(routes, buildRoutes(resultingMatches, annotations, serviceKey, miRefsPerService)...)
	}

	sort.SliceStable(routes, func(i, j int) bool {
		return routes[i].Match < routes[j].Match
	})
	return routes
}

func buildRoutes(hostPathRules map[string]string, annotations map[string]string, serviceKey ServiceKey, miRefsPerService map[ServiceKey][]v1alpha1.MiddlewareRef) []*v1alpha1.Route {
	var routes []*v1alpha1.Route
	for hosts, paths := range hostPathRules {
		var match []string
		if len(hosts) > 0 {
			match = append(match, hosts)
		}
		if len(paths) > 0 {
			match = append(match, paths)
		}
		routes = append(routes, &v1alpha1.Route{
			Match:    strings.Join(match, " && "),
			Kind:     "Rule",
			Priority: getIntValue(annotations, annotationKubernetesPriority, 0),
			Services: []v1alpha1.Service{
				{
					LoadBalancerSpec: serviceKey.LoadBalancerSpec,
				}},
			Middlewares: miRefsPerService[serviceKey],
		})
	}
	return routes
}

func createMiddewareRefsKey(miRefs []v1alpha1.MiddlewareRef) string {
	var miNames []string
	for _, miRef := range miRefs {
		miNames = append(miNames, miRef.Name)
	}
	sort.Strings(miNames)
	return fmt.Sprintf("%q", miNames)
}

func createMatchRule(ruleValues []string, ruleType string) string {
	sort.Strings(ruleValues)
	var ticked []string
	for _, ruleValue := range ruleValues {
		if ruleValue != "" {
			ticked = append(ticked, "`"+ruleValue+"`")
		}
	}
	if len(ticked) == 0 {
		return ""
	}
	return fmt.Sprintf("%s(%s)", ruleType, strings.Join(ticked, ","))
}

func extractRuleType(annotations map[string]string) (string, bool, error) {
	var stripPrefix bool
	ruleType := getStringValue(annotations, annotationKubernetesRuleType, ruleTypePathPrefix)

	switch ruleType {
	case ruleTypePath, ruleTypePathPrefix:
	case ruleTypePathStrip:
		ruleType = ruleTypePath
		stripPrefix = true
	case ruleTypePathPrefixStrip:
		ruleType = ruleTypePathPrefix
		stripPrefix = true
	case ruleTypeReplacePath:
		log.Printf("Using %s as %s will be deprecated in the future. Please use the %s annotation instead", ruleType, annotationKubernetesRuleType, annotationKubernetesRequestModifier)
	default:
		return "", false, fmt.Errorf("cannot use non-matcher rule: %q", ruleType)
	}

	return ruleType, stripPrefix, nil
}

func toRef(mi *v1alpha1.Middleware) v1alpha1.MiddlewareRef {
	return v1alpha1.MiddlewareRef{
		Name:      mi.Name,
		Namespace: mi.Namespace,
	}
}

func logUnsupported(ingress *networking.Ingress) {
	unsupportedAnnotations := map[string]string{
		annotationKubernetesErrorPages:                      "See https://docs.traefik.io/middlewares/errorpages/",
		annotationKubernetesBuffering:                       "See https://docs.traefik.io/middlewares/buffering/",
		annotationKubernetesCircuitBreakerExpression:        "See https://docs.traefik.io/middlewares/circuitbreaker/",
		annotationKubernetesMaxConnAmount:                   "See https://docs.traefik.io/middlewares/inflightreq/",
		annotationKubernetesMaxConnExtractorFunc:            "See https://docs.traefik.io/middlewares/inflightreq/",
		annotationKubernetesResponseForwardingFlushInterval: "See https://docs.traefik.io/providers/kubernetes-crd/",
		annotationKubernetesLoadBalancerMethod:              "See https://docs.traefik.io/providers/kubernetes-crd/",
		annotationKubernetesPreserveHost:                    "See https://docs.traefik.io/providers/kubernetes-crd/",
		annotationKubernetesSessionCookieName:               "Not supported yet.",
		annotationKubernetesAffinity:                        "Not supported yet.",
		annotationKubernetesAuthRealm:                       "See https://docs.traefik.io/middlewares/basicauth/",
		annotationKubernetesServiceWeights:                  "See https://docs.traefik.io/providers/kubernetes-crd/",
	}

	for annot, msg := range unsupportedAnnotations {
		if getStringValue(ingress.GetAnnotations(), annot, "") != "" {
			fmt.Printf("%s/%s: The annotation %s must be converted manually. %s", ingress.GetNamespace(), ingress.GetName(), annot, msg)
		}
	}
}

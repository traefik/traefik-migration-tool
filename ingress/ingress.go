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
	"k8s.io/apimachinery/pkg/runtime"
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
	content, err := ioutil.ReadFile(filepath.Join(srcDir, filename))
	if err != nil {
		return err
	}

	err = os.MkdirAll(dstDir, 0755)
	if err != nil {
		return err
	}

	parts := strings.Split(string(content), separator)
	var ymlBytes []string
	for _, part := range parts {
		if part == "\n" || part == "" {
			continue
		}

		object, err := parseYaml([]byte(part))
		if err != nil {
			log.Printf("err while reading yaml: %v", err)
			ymlBytes = append(ymlBytes, part)
			continue
		}

		var ingress *networking.Ingress
		switch i := object.(type) {
		case *extensions.Ingress:
			ingress, err = extensionsToNetworking(i)
			if err != nil {
				return err
			}
		case *networking.Ingress:
			ingress = i
		default:
			log.Printf("object is not an ingress ignore it: %T", object)
			ymlBytes = append(ymlBytes, part)
			continue
		}

		objects := convertIngress(ingress)
		for _, object := range objects {
			yml, err := encodeYaml(object, v1alpha1.GroupName+groupSuffix)
			if err != nil {
				return err
			}
			ymlBytes = append(ymlBytes, yml)
		}
	}

	return ioutil.WriteFile(filepath.Join(dstDir, filename), []byte(strings.Join(ymlBytes, separator+"\n")), 0666)
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
	ingressRoute.Spec.Routes = routes

	middlewares = append(middlewares, mi...)

	sort.Slice(middlewares, func(i, j int) bool { return middlewares[i].Name < middlewares[j].Name })

	objects := []runtime.Object{ingressRoute}
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return objects
}

func createRoutes(namespace string, rules []networking.IngressRule, annotations map[string]string, middlewareRefs []v1alpha1.MiddlewareRef) ([]v1alpha1.Route, []*v1alpha1.Middleware, error) {
	ruleType, stripPrefix, err := extractRuleType(annotations)
	if err != nil {
		return nil, nil, err
	}

	var mis []*v1alpha1.Middleware

	var routes []v1alpha1.Route

	for _, rule := range rules {
		for _, path := range rule.HTTP.Paths {
			var miRefs = make([]v1alpha1.MiddlewareRef, 0, 1)
			miRefs = append(miRefs, middlewareRefs...)

			var rules []string

			if len(rule.Host) > 0 {
				rules = append(rules, fmt.Sprintf("Host(`%s`)", rule.Host))
			}

			if len(path.Path) > 0 {
				rules = append(rules, fmt.Sprintf("%s(`%s`)", ruleType, path.Path))

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

			if len(rules) > 0 {
				sort.Slice(miRefs, func(i, j int) bool { return miRefs[i].Name < miRefs[j].Name })

				routes = append(routes, v1alpha1.Route{
					Match:    strings.Join(rules, " && "),
					Kind:     "Rule",
					Priority: getIntValue(annotations, annotationKubernetesPriority, 0),
					Services: []v1alpha1.Service{
						{
							LoadBalancerSpec: v1alpha1.LoadBalancerSpec{
								Name:      path.Backend.ServiceName,
								Namespace: namespace,
								Kind:      "Service",
								// TODO pas de port en string dans ingressRoute ?
								Port:   path.Backend.ServicePort.IntVal,
								Scheme: getStringValue(annotations, annotationKubernetesProtocol, ""),
							},
						}},
					Middlewares: miRefs,
				})
			}
		}
	}

	return routes, mis, nil
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
		annotationKubernetesErrorPages:                      "See https://docs.traefik.io/v2.0/middlewares/errorpages/",
		annotationKubernetesBuffering:                       "See https://docs.traefik.io/v2.0/middlewares/buffering/",
		annotationKubernetesCircuitBreakerExpression:        "See https://docs.traefik.io/v2.0/middlewares/circuitbreaker/",
		annotationKubernetesMaxConnAmount:                   "See https://docs.traefik.io/v2.0/middlewares/inflightreq/",
		annotationKubernetesMaxConnExtractorFunc:            "See https://docs.traefik.io/v2.0/middlewares/inflightreq/",
		annotationKubernetesResponseForwardingFlushInterval: "See https://docs.traefik.io/v2.0/providers/kubernetes-crd/",
		annotationKubernetesLoadBalancerMethod:              "See https://docs.traefik.io/v2.0/providers/kubernetes-crd/",
		annotationKubernetesPreserveHost:                    "See https://docs.traefik.io/v2.0/providers/kubernetes-crd/",
		annotationKubernetesSessionCookieName:               "Not supported yet.",
		annotationKubernetesAffinity:                        "Not supported yet.",
		annotationKubernetesAuthRealm:                       "See https://docs.traefik.io/v2.0/middlewares/basicauth/",
		annotationKubernetesServiceWeights:                  "See https://docs.traefik.io/v2.0/providers/kubernetes-crd/",
	}

	for annot, msg := range unsupportedAnnotations {
		if getStringValue(ingress.GetAnnotations(), annot, "") != "" {
			fmt.Printf("%s/%s: The annotation %s must be converted manually. %s", ingress.GetNamespace(), ingress.GetName(), annot, msg)
		}
	}
}

package ingress

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
)

const separator = "---"

const groupSuffix = "/v1alpha1"

const (
	ruleTypePath            = "Path"
	ruleTypePathPrefix      = "PathPrefix"
	ruleTypePathStrip       = "PathStrip"
	ruleTypePathPrefixStrip = "PathPrefixStrip"
	ruleTypeAddPrefix       = "AddPrefix"
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

	files := strings.Split(string(content), separator)
	var ymlBytes []string
	for _, file := range files {
		if file == "\n" || file == "" {
			continue
		}

		object, err := parseYaml([]byte(file))
		if err != nil {
			log.Printf("err while reading yaml: %v", err)
			ymlBytes = append(ymlBytes, file)
			continue
		}

		ingress, ok := object.(*extensionsv1beta1.Ingress)
		if !ok {
			log.Printf("object is not an ingress ignore it: %T", object)
			ymlBytes = append(ymlBytes, file)
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

// convertIngress converts an *extensionsv1beta1.Ingress to a slice of runtime.Object (IngressRoute and Middlewares)
func convertIngress(ingress *extensionsv1beta1.Ingress) []runtime.Object {
	ingressRoute := &v1alpha1.IngressRoute{
		ObjectMeta: v1.ObjectMeta{Name: ingress.Name, Namespace: ingress.Namespace, Annotations: map[string]string{}},
		Spec: v1alpha1.IngressRouteSpec{
			EntryPoints: getSliceStringValue(ingress.Annotations, annotationKubernetesFrontendEntryPoints),
		},
	}

	ingressClass := getStringValue(ingress.Annotations, annotationKubernetesIngressClass, "")
	if len(ingressClass) > 0 {
		ingressRoute.Annotations[annotationKubernetesIngressClass] = ingressClass
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

	// errorPages middleware
	middlewares = append(middlewares, getErrorPages(ingress)...)

	// rateLimit middleware
	middlewares = append(middlewares, getRateLimit(ingress)...)

	var miRefs []v1alpha1.MiddlewareRef
	for _, middleware := range middlewares {
		miRefs = append(miRefs, v1alpha1.MiddlewareRef{
			Name:      middleware.Name,
			Namespace: middleware.Namespace,
		})
	}

	routes, mi := createRoutes(ingress.Namespace, ingress.Spec.Rules, ingress.Annotations, miRefs)

	ingressRoute.Spec.Routes = routes

	middlewares = append(middlewares, mi...)

	objects := []runtime.Object{ingressRoute}
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return objects
}

func createRoutes(namespace string, rules []extensionsv1beta1.IngressRule, annotations map[string]string, middlewareRefs []v1alpha1.MiddlewareRef) ([]v1alpha1.Route, []*v1alpha1.Middleware) {

	ruleType := getStringValue(annotations, annotationKubernetesRuleType, ruleTypePathPrefix)

	var modifierType string
	switch ruleType {
	case ruleTypePath, ruleTypePathPrefix:
	case ruleTypePathStrip, ruleTypePathPrefixStrip:
		// FIXME
		ruleType = ruleTypePathPrefix
		modifierType = "StripPrefix"
	default:
		ruleType = ruleTypePathPrefix
	}
	
	var mi []*v1alpha1.Middleware

	var routes []v1alpha1.Route

	for _, rule := range rules {
		for _, path := range rule.HTTP.Paths {
			var miRefs = make([]v1alpha1.MiddlewareRef, 0, 1)

			miRefs = append(miRefs, middlewareRefs...)

			var rules []string
			middlewareName := rule.Host + path.Path

			if len(rule.Host) > 0 {
				rules = append(rules, fmt.Sprintf("Host(`%s`)", rule.Host))
			}

			if len(path.Path) > 0 {
				rules = append(rules, fmt.Sprintf("%s(`%s`)", ruleType, path.Path))

				if modifierType == "StripPrefix" {
					mi = append(mi, &v1alpha1.Middleware{
						ObjectMeta: v1.ObjectMeta{Name: middlewareName, Namespace: namespace},
						Spec: dynamic.Middleware{
							StripPrefix: &dynamic.StripPrefix{Prefixes: []string{path.Path}},
						},
					})

					miRefs = append(miRefs, v1alpha1.MiddlewareRef{
						Name:      middlewareName,
						Namespace: namespace,
					})
				}

				if rewriteTarget := getStringValue(annotations, annotationKubernetesRewriteTarget, ""); rewriteTarget != "" {
					middlewareName := "replace-path-" + rule.Host + path.Path
					middleware := &v1alpha1.Middleware{
						ObjectMeta: v1.ObjectMeta{Name: middlewareName, Namespace: namespace},
						Spec: dynamic.Middleware{
							ReplacePathRegex: &dynamic.ReplacePathRegex{
								Regex:       fmt.Sprintf("^%s(.*)", path.Path),
								Replacement: fmt.Sprintf("%s$1", strings.TrimRight(rewriteTarget, "/")),
							},
						},
					}
					mi = append(mi, middleware)
					miRefs = append(miRefs, v1alpha1.MiddlewareRef{
						Name:      middlewareName,
						Namespace: namespace,
					})
				}
			}

			redirect := getFrontendRedirect(namespace, annotations, rule.Host+path.Path, path.Path)
			if redirect != nil {
				mi = append(mi, redirect)
				miRefs = append(miRefs, v1alpha1.MiddlewareRef{
					Name:      redirect.Name,
					Namespace: namespace,
				})
			}

			if len(rules) > 0 {
				route := v1alpha1.Route{
					Match:    strings.Join(rules, " && "),
					Kind:     "Rule",
					Priority: getIntValue(annotations, annotationKubernetesPriority, 0),
					Services: []v1alpha1.Service{{
						Name: path.Backend.ServiceName,
						// TODO pas de port en string dans ingressRoute ?
						Port:   path.Backend.ServicePort.IntVal,
						Scheme: getStringValue(annotations, annotationKubernetesProtocol, ""),
					}},
					Middlewares: miRefs,
				}

				routes = append(routes, route)
			}
		}
	}
	return routes, mi
}

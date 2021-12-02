// Package ingress convert Ingress to IngressRoute.
package ingress

import (
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"

	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	netv1 "k8s.io/api/networking/v1"
	netv1beta1 "k8s.io/api/networking/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/intstr"
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

// Convert converts all ingress in a src into a dstDir.
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
	infos, err := os.ReadDir(src)
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

	err = os.MkdirAll(dstDir, 0o755)
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

		var ingress *netv1.Ingress
		switch obj := object.(type) {
		case *extv1beta1.Ingress:
			ingress, err = extensionsToNetworkingV1(obj)
			if err != nil {
				return err
			}
		case *netv1beta1.Ingress:
			ingress, err = networkingV1beta1ToV1(obj)
			if err != nil {
				return err
			}
		case *netv1.Ingress:
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

	return os.WriteFile(filepath.Join(dstDir, filename), []byte(strings.Join(fragments, separator+"\n")), 0o666)
}

func expandFileContent(filePath string) ([]byte, error) {
	content, err := os.ReadFile(filePath)
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
		apiVersion := obj.GetAPIVersion()

		if (apiVersion == "extensions/v1beta1" || apiVersion == "networking.k8s.io/v1beta1" || apiVersion == "networking.k8s.io/v1") && obj.GetKind() == "Ingress" {
			toConvert = append(toConvert, obj)
		} else {
			toKeep = append(toKeep, elt)
		}
	}

	return toKeep, toConvert
}

// convertIngress converts an *networking.Ingress to a slice of runtime.Object (IngressRoute and Middlewares).
func convertIngress(ingress *netv1.Ingress) []runtime.Object {
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

	routes, mis, err := createRoutes(ingress.GetNamespace(), ingress.Spec.Rules, ingress.GetAnnotations(), miRefs)
	if err != nil {
		log.Println(err)
		return nil
	}
	ingressRoute.Spec.Routes = routes

	middlewares = append(middlewares, mis...)

	sort.Slice(middlewares, func(i, j int) bool { return middlewares[i].Name < middlewares[j].Name })

	objects := []runtime.Object{ingressRoute}
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return objects
}

func createRoutes(namespace string, rules []netv1.IngressRule, annotations map[string]string, middlewareRefs []v1alpha1.MiddlewareRef) ([]v1alpha1.Route, []*v1alpha1.Middleware, error) {
	ruleType, stripPrefix, err := extractRuleType(annotations)
	if err != nil {
		return nil, nil, err
	}

	var mis []*v1alpha1.Middleware

	var routes []v1alpha1.Route

	for _, rule := range rules {
		for _, path := range rule.HTTP.Paths {
			miRefs := make([]v1alpha1.MiddlewareRef, 0, 1)
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
								Name:      path.Backend.Service.Name,
								Namespace: namespace,
								Kind:      "Service",
								Port:      toPort(path.Backend.Service.Port),
								Scheme:    getStringValue(annotations, annotationKubernetesProtocol, ""),
							},
						},
					},
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

func toPort(p netv1.ServiceBackendPort) intstr.IntOrString {
	if p.Name != "" {
		return intstr.FromString(p.Name)
	}

	return intstr.FromInt(int(p.Number))
}

func logUnsupported(ingress *netv1.Ingress) {
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

// https://kubernetes.io/docs/concepts/overview/working-with-objects/names/#names
func normalizeObjectName(name string) string {
	fn := func(c rune) bool {
		return !unicode.IsLetter(c) && !unicode.IsNumber(c) && c != '.' && c != '-'
	}

	return strings.Join(strings.FieldsFunc(name, fn), "-")
}

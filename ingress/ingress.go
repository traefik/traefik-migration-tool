package ingress

import (
	"bytes"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/mitchellh/hashstructure"
	"github.com/sirupsen/logrus"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

const separator string = "---"

const (
	ruleTypePath            = "Path"
	ruleTypePathPrefix      = "PathPrefix"
	ruleTypePathStrip       = "PathStrip"
	ruleTypePathPrefixStrip = "PathPrefixStrip"
	ruleTypeAddPrefix       = "AddPrefix"
)

func headerMiddleware(annotations map[string]string) *dynamic.Middleware {
	headers := &dynamic.Headers{
		CustomRequestHeaders:    getMapValue(annotations, annotationKubernetesCustomRequestHeaders),
		CustomResponseHeaders:   getMapValue(annotations, annotationKubernetesCustomResponseHeaders),
		AllowedHosts:            getSliceStringValue(annotations, annotationKubernetesAllowedHosts),
		HostsProxyHeaders:       getSliceStringValue(annotations, annotationKubernetesProxyHeaders),
		SSLForceHost:            getBoolValue(annotations, annotationKubernetesSSLForceHost, false),
		SSLRedirect:             getBoolValue(annotations, annotationKubernetesSSLRedirect, false),
		SSLTemporaryRedirect:    getBoolValue(annotations, annotationKubernetesSSLTemporaryRedirect, false),
		SSLHost:                 getStringValue(annotations, annotationKubernetesSSLHost, ""),
		SSLProxyHeaders:         getMapValue(annotations, annotationKubernetesSSLProxyHeaders),
		STSSeconds:              getInt64Value(annotations, annotationKubernetesHSTSMaxAge, 0),
		STSIncludeSubdomains:    getBoolValue(annotations, annotationKubernetesHSTSIncludeSubdomains, false),
		STSPreload:              getBoolValue(annotations, annotationKubernetesHSTSPreload, false),
		ForceSTSHeader:          getBoolValue(annotations, annotationKubernetesForceHSTSHeader, false),
		FrameDeny:               getBoolValue(annotations, annotationKubernetesFrameDeny, false),
		CustomFrameOptionsValue: getStringValue(annotations, annotationKubernetesCustomFrameOptionsValue, ""),
		ContentTypeNosniff:      getBoolValue(annotations, annotationKubernetesContentTypeNosniff, false),
		BrowserXSSFilter:        getBoolValue(annotations, annotationKubernetesBrowserXSSFilter, false),
		CustomBrowserXSSValue:   getStringValue(annotations, annotationKubernetesCustomBrowserXSSValue, ""),
		ContentSecurityPolicy:   getStringValue(annotations, annotationKubernetesContentSecurityPolicy, ""),
		PublicKey:               getStringValue(annotations, annotationKubernetesPublicKey, ""),
		ReferrerPolicy:          getStringValue(annotations, annotationKubernetesReferrerPolicy, ""),
		IsDevelopment:           getBoolValue(annotations, annotationKubernetesIsDevelopment, false),
	}

	if headers.HasCustomHeadersDefined() || headers.HasCorsHeadersDefined() || headers.HasSecureHeadersDefined() {
		return &dynamic.Middleware{
			Headers: headers,
		}
	}
	return nil
}

// ConvertIngress converts an *extensionsv1beta1.Ingress to a slice of runtime.Object (IngressRoute and Middlewares)
func ConvertIngress(ingress *extensionsv1beta1.Ingress) []runtime.Object {
	ingressRoute := &v1alpha1.IngressRoute{ObjectMeta: v1.ObjectMeta{Name: ingress.Name, Namespace: ingress.Namespace, Annotations: map[string]string{}}}

	ingressClass := getStringValue(ingress.Annotations, annotationKubernetesIngressClass, "")
	if len(ingressClass) > 0 {
		ingressRoute.Annotations[annotationKubernetesIngressClass] = ingressClass
	}

	ingressRoute.Spec.EntryPoints = getSliceStringValue(ingress.Annotations, annotationKubernetesFrontendEntryPoints)

	var middlewares []*v1alpha1.Middleware

	headerMiddleware := headerMiddleware(ingress.Annotations)
	if headerMiddleware != nil {
		hash, err := hashstructure.Hash(headerMiddleware, nil)
		if err != nil {
			logrus.Fatal(err)
		}

		middlewares = append(middlewares, &v1alpha1.Middleware{
			Spec:       *headerMiddleware,
			ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "headers", hash), Namespace: ingress.Namespace},
		})
	}

	ingressRoute.Spec.Routes, middlewares = createRoutesFromRules(ingress.Namespace, ingress.Spec.Rules, ingress.Annotations)

	var objects []runtime.Object
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return append(objects, ingressRoute)
}

func createRoutesFromRules(namespace string, rules []extensionsv1beta1.IngressRule, annotations map[string]string, previousMiddlewares []*v1alpha1.Middleware) ([]v1alpha1.Route, []*v1alpha1.Middleware) {
	ruleType := getStringValue(annotations, annotationKubernetesRuleType, ruleTypePathPrefix)
	var middlewares []*v1alpha1.Middleware
	var modifierType string

	switch ruleType {
	case ruleTypePath, ruleTypePathPrefix:
	case ruleTypePathStrip, ruleTypePathPrefixStrip:
		ruleType = ruleTypePathPrefix
		modifierType = "StripPrefix"
	default:
		ruleType = ruleTypePathPrefix
	}

	var routes []v1alpha1.Route
	for _, rule := range rules {
		for _, path := range rule.HTTP.Paths {
			var rules []string
			middlewareName := rule.Host + path.Path
			if len(rule.Host) > 0 {
				rules = append(rules, fmt.Sprintf("Host(`%s`)", rule.Host))
			}
			if len(path.Path) > 0 {
				rules = append(rules, fmt.Sprintf("%s(`%s`)", ruleType, path.Path))
				if modifierType == "StripPrefix" {
					middlewares = append(middlewares, &v1alpha1.Middleware{
						ObjectMeta: v1.ObjectMeta{
							Name:      middlewareName,
							Namespace: namespace,
						},
						Spec: dynamic.Middleware{
							StripPrefix: &dynamic.StripPrefix{Prefixes: []string{path.Path}},
						},
					})
				}
			}

			if len(rules) > 0 {
				route := v1alpha1.Route{
					Match:    strings.Join(rules, " && "),
					Kind:     "Rule",
					Priority: getIntValue(annotations, annotationKubernetesPriority, 0),
					Services: []v1alpha1.Service{
						{
							Name: path.Backend.ServiceName,
							// TODO pas de port en string dans ingressRoute ?
							Port:   path.Backend.ServicePort.IntVal,
							Scheme: getStringValue(annotations, annotationKubernetesProtocol, ""),
						},
					},
					Middlewares: make([]v1alpha1.MiddlewareRef, 0, 1),
				}

				if modifierType != "" {
					route.Middlewares = append(route.Middlewares, v1alpha1.MiddlewareRef{
							Name:      middlewareName,
							Namespace: namespace,
						})
				}

				for _, middleware := range previousMiddlewares {
					route.Middlewares = append(route.Middlewares, v1alpha1.MiddlewareRef{
						Name:      middleware.Name,
						Namespace: middleware.Namespace,
					})
				}
				routes = append(routes, route)
			}
		}
	}
	return routes, middlewares
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
	inputFile := filepath.Join(srcDir, filename)
	bytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dstDir, 0755)
	if err != nil {
		return err
	}

	files := strings.Split(string(bytes), separator)
	var ymlBytes []string
	for _, file := range files {
		if file == "\n" || file == "" {
			continue
		}
		object, err := mustParseYaml([]byte(file))
		if err != nil {
			logrus.Debugf("err while reading yaml: %v", err)
			ymlBytes = append(ymlBytes, file)
			continue
		}
		ingress, ok := object.(*extensionsv1beta1.Ingress)
		if !ok {
			logrus.Debugf("object is not an ingress ignore it: %T", object)
			ymlBytes = append(ymlBytes, file)
			continue
		}
		objects := ConvertIngress(ingress)
		for _, object := range objects {
			yml, err := mustEncodeYaml(object, v1alpha1.GroupName+"/v1alpha1")
			if err != nil {
				return err
			}
			ymlBytes = append(ymlBytes, yml)
		}
	}

	return ioutil.WriteFile(filepath.Join(dstDir, filename), []byte(strings.Join(ymlBytes, separator+"\n")), 0666)
}

func mustEncodeYaml(object runtime.Object, groupName string) (string, error) {
	info, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), "application/yaml")
	if !ok {
		return "", errors.New("unsupported media type application/yaml")
	}

	gv, err := schema.ParseGroupVersion(groupName)
	if err != nil {
		return "", err
	}

	buffer := bytes.NewBuffer([]byte{})

	v1alpha1.AddToScheme(scheme.Scheme)
	err = scheme.Codecs.EncoderForVersion(info.Serializer, gv).Encode(object, buffer)
	if err != nil {
		return "", err

	}
	return buffer.String(), nil
}

// mustParseYaml parses a YAML to objects.
func mustParseYaml(content []byte) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(content, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %s", err)
	}

	return obj, nil
}

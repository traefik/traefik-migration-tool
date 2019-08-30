package ingress

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
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

// ConvertIngress converts an *extensionsv1beta1.Ingress to a slice of runtime.Object (IngressRoute and Middlewares)
func ConvertIngress(ingress *extensionsv1beta1.Ingress) []runtime.Object {
	ingressRoute := &v1alpha1.IngressRoute{ObjectMeta: v1.ObjectMeta{Name: ingress.Name, Namespace: ingress.Namespace, Annotations: map[string]string{}}}

	ingressRoute.Annotations[annotationKubernetesIngressClass] = ingress.Annotations[annotationKubernetesIngressClass]

	// TODO Handle compatibility mapping
	// if entrypoints, ok := ingress.Annotations[compatibilityMapping[annotationKubernetesFrontendEntryPoints]]; ok {
	// 	ingressRoute.Spec.EntryPoints = strings.Split(entrypoints, ",")
	// }

	if entrypoints, ok := ingress.Annotations[annotationKubernetesFrontendEntryPoints]; ok {
		ingressRoute.Spec.EntryPoints = strings.Split(entrypoints, ",")
	}

	var middlewares []*v1alpha1.Middleware
	ingressRoute.Spec.Routes, middlewares = createRoutesFromRules(ingress.Namespace, ingress.Spec.Rules, ingress.Annotations[annotationKubernetesRuleType])

	var objects []runtime.Object
	for _, middleware := range middlewares {
		objects = append(objects, middleware)
	}

	return append(objects, ingressRoute)
}

func createRoutesFromRules(namespace string, rules []extensionsv1beta1.IngressRule, ruleType string) ([]v1alpha1.Route, []*v1alpha1.Middleware) {
	var middlewares []*v1alpha1.Middleware
	var modifierType string
	// TODO handle ruleType withMiddleware
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
					Priority: 0,
					Services: []v1alpha1.Service{
						{
							Name: path.Backend.ServiceName,
							// TODO pas de port en string dans ingressRoute ?
							Port: path.Backend.ServicePort.IntVal,
						},
					},
				}
				if modifierType != "" {
					route.Middlewares = []v1alpha1.MiddlewareRef{
						{
							Name: middlewareName,
							Namespace:namespace,
						},
					}
				}
				routes = append(routes, route)
			}
		}
	}
	return routes, middlewares
}

// Convert converts all ingress in a srcDir into a dstDir
func Convert(srcDir, dstDir string) error {
	info, err := os.Stat(srcDir)
	if err != nil {
		return err
	}

	if info.IsDir() {
		dir := info.Name()
		infos, err := ioutil.ReadDir(srcDir)
		if err != nil {
			return err
		}
		for _, info := range infos {
			newSrc := path.Join(srcDir, info.Name())
			newDst := path.Join(dstDir, dir)
			err := Convert(newSrc, newDst)
			if err != nil {
				return err
			}
		}
	} else {
		filename := info.Name()
		srcPath := filepath.Dir(srcDir)
		err := convertFile(srcPath, dstDir, filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func convertFile(srcDir, dstDir, filename string) error {
	inputFile := path.Join(srcDir, filename)
	outputFile := path.Join(dstDir, filename)

	bytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	err = os.MkdirAll(dstDir, 0777)
	if err != nil {
		return err
	}

	files := strings.Split(string(bytes), "---")
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
			ymlBytes = append(ymlBytes, mustEncodeYaml(object, v1alpha1.GroupName+"/v1alpha1"))
		}
	}

	return ioutil.WriteFile(outputFile, []byte(strings.Join(ymlBytes, separator)), 0666)
}

func mustEncodeYaml(object runtime.Object, groupName string) string {
	info, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), "application/yaml")
	if !ok {
		panic("oops")
	}

	gv, err := schema.ParseGroupVersion(groupName)
	if err != nil {
		panic(err)
	}

	buffer := bytes.NewBuffer([]byte{})

	v1alpha1.AddToScheme(scheme.Scheme)
	err = scheme.Codecs.EncoderForVersion(info.Serializer, gv).Encode(object, buffer)
	if err != nil {
		panic(err)
	}
	return buffer.String()
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

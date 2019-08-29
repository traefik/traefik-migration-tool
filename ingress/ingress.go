package ingress

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

const separator string = "---"

func ConvertIngress(ingress *extensionsv1beta1.Ingress) []runtime.Object {
	ingressRoute := &v1alpha1.IngressRoute{ObjectMeta: v1.ObjectMeta{Name: ingress.Name, Namespace: ingress.Namespace}}

	for _, rule := range ingress.Spec.Rules {
		for _, path := range rule.HTTP.Paths {
			var rules []string
			if len(rule.Host) > 0 {
				rules = append(rules, fmt.Sprintf("Host(`%s`)", rule.Host))
			}
			if len(path.Path) > 0 {
				rules = append(rules, fmt.Sprintf("PathPrefix(`%s`)", path.Path))
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
				ingressRoute.Spec.Routes = append(ingressRoute.Spec.Routes, route)
			}
		}
	}

	return []runtime.Object{ingressRoute}
}

func Convert(src, dstDir string) error {
	info, err := os.Stat(src)
	if err != nil {
		return err
	}

	if info.IsDir() {
		dir := info.Name()
		infos, err := ioutil.ReadDir(src)
		if err != nil {
			return err
		}
		for _, info := range infos {
			newSrc := path.Join(src, info.Name())
			newDst := path.Join(dstDir, dir)
			err := Convert(newSrc, newDst)
			if err != nil {
				return err
			}
		}
	} else {
		filename := info.Name()
		srcPath := filepath.Dir(src)
		err := ConvertFile(srcPath, dstDir, filename)
		if err != nil {
			return err
		}
	}
	return nil
}

func ConvertFile(srcDir, dstDir, filename string) error {
	inputFile := path.Join(srcDir, filename)
	outputFile := path.Join(dstDir, filename)

	bytes, err := ioutil.ReadFile(inputFile)
	if err != nil {
		return err
	}

	err = os.MkdirAll(filepath.Dir(outputFile), 0777)
	if err != nil {
		return err
	}

	files := strings.Split(string(bytes), "---")
	var ymlBytes []string
	for _, file := range files {
		if file == "\n" || file == "" {
			continue
		}
		object, err := MustParseYaml([]byte(file))
		if err != nil {
			ymlBytes = append(ymlBytes, file)
			continue
		}
		ingress, ok := object.(*extensionsv1beta1.Ingress)
		if !ok {
			ymlBytes = append(ymlBytes, file)
			continue
		}
		objects := ConvertIngress(ingress)
		for _, object := range objects {
			ymlBytes = append(ymlBytes, MustEncodeYaml(object, v1alpha1.GroupName+"/v1alpha1"))
		}
	}

	return ioutil.WriteFile(outputFile, []byte(strings.Join(ymlBytes, separator)), 0666)
}

func MustEncodeYaml(object runtime.Object, groupName string) string {
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

// MustParseYaml parses a YAML to objects.
func MustParseYaml(content []byte) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode
	obj, _, err := decode(content, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %s", err)
	}

	return obj, nil
}

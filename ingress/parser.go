package ingress

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	extv1beta1 "k8s.io/api/extensions/v1beta1"
	netv1 "k8s.io/api/networking/v1"
	netv1beta1 "k8s.io/api/networking/v1beta1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
)

func extensionsToNetworkingV1(ing *extv1beta1.Ingress) (*netv1.Ingress, error) {
	data, err := ing.Marshal()
	if err != nil {
		return nil, err
	}

	ni := &netv1beta1.Ingress{}
	if err := ni.Unmarshal(data); err != nil {
		return nil, err
	}

	return networkingV1beta1ToV1(ni)
}

func networkingV1beta1ToV1(ing *netv1beta1.Ingress) (*netv1.Ingress, error) {
	data, err := ing.Marshal()
	if err != nil {
		return nil, err
	}

	ni := &netv1.Ingress{}
	if err := ni.Unmarshal(data); err != nil {
		return nil, err
	}

	if ing.Spec.Backend != nil {
		ni.Spec.DefaultBackend = &netv1.IngressBackend{
			Resource: ing.Spec.Backend.Resource,
			Service: &netv1.IngressServiceBackend{
				Name: ing.Spec.Backend.ServiceName,
				Port: toServiceBackendPort(ing.Spec.Backend.ServicePort),
			},
		}
	}

	for ri, rule := range ing.Spec.Rules {
		for pi, path := range rule.HTTP.Paths {
			ni.Spec.Rules[ri].HTTP.Paths[pi].Backend = netv1.IngressBackend{
				Service: &netv1.IngressServiceBackend{
					Name: path.Backend.ServiceName,
					Port: toServiceBackendPort(path.Backend.ServicePort),
				},
			}
		}
	}

	return ni, nil
}

func toServiceBackendPort(p intstr.IntOrString) netv1.ServiceBackendPort {
	var port netv1.ServiceBackendPort
	switch p.Type {
	case intstr.Int:
		port.Number = p.IntVal
	case intstr.String:
		port.Name = p.StrVal
	}

	return port
}

func encodeYaml(object runtime.Object, groupName string) (string, error) {
	err := v1alpha1.AddToScheme(scheme.Scheme)
	if err != nil {
		return "", err
	}

	info, ok := runtime.SerializerInfoForMediaType(scheme.Codecs.SupportedMediaTypes(), "application/yaml")
	if !ok {
		return "", errors.New("unsupported media type application/yaml")
	}

	gv, err := schema.ParseGroupVersion(groupName)
	if err != nil {
		return "", err
	}

	buffer := bytes.NewBuffer([]byte{})
	err = scheme.Codecs.EncoderForVersion(info.Serializer, gv).Encode(object, buffer)
	if err != nil {
		return "", err
	}
	return buffer.String(), nil
}

func parseYaml(content []byte) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, _, err := decode(content, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %w", err)
	}

	return obj, nil
}

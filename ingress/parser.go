package ingress

import (
	"bytes"
	"errors"
	"fmt"

	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/kubernetes/scheme"
)

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
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %s", err)
	}

	return obj, nil
}

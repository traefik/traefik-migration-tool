package service

import (
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	v1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
)

const separator = "---"

// NamePortMapping is service,servicePortName,ServicePort mapping relationship
type NamePortMapping struct {
	mux             *sync.RWMutex
	serviceNamePort map[string]map[string]int32
}

// AddNamePortMapping add NamePortMapping to index
func (c *NamePortMapping) AddNamePortMapping(namespace, service string, mapping map[string]int32) error {
	if len(mapping) == 0 {
		return nil
	}

	c.mux.Lock()
	defer c.mux.Unlock()

	key := fmt.Sprintf("%s-%s", namespace, service)
	c.serviceNamePort[key] = mapping
	return nil
}

// GetServicePortWithName get service port from NamePortMapping
func (c *NamePortMapping) GetServicePortWithName(namespace, service, name string) (int32, error) {
	c.mux.RLock()
	defer c.mux.RUnlock()
	var port int32

	key := fmt.Sprintf("%s-%s", namespace, service)

	if p, ok := c.serviceNamePort[key][name]; ok {
		port = p
	} else {
		port = 0
	}
	return port, nil
}

// NewNamePortMapping Initialize and return NamePortMapping sturct
func NewNamePortMapping() (*NamePortMapping, error) {
	snp := NamePortMapping{
		mux:             new(sync.RWMutex),
		serviceNamePort: make(map[string]map[string]int32),
	}
	return &snp, nil
}

// BuildIndex build  NamePortMapping
func BuildIndex(path string) (*NamePortMapping, error) {
	snp, err := NewNamePortMapping()
	if err != nil {
		return snp, err
	}

	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		var context []byte
		context, err = ioutil.ReadFile(path)

		if err != nil {
			fmt.Println(err)
			return nil, err
		}

		files := strings.Split(string(context), separator)
		for _, file := range files {
			if file == "\n" || file == "" {
				continue
			}

			var namespace, service string
			var mapping map[string]int32

			namespace, service, mapping, err = getNameAndPortMapping([]byte(file))
			if err != nil {
				continue
			}

			err = snp.AddNamePortMapping(namespace, service, mapping)
			if err != nil {
				return snp, err
			}
		}

		return snp, nil
	}

	dir := info.Name()
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, info := range infos {
		newPath := filepath.Join(path, info.Name())
		err := buildIndex(newPath, snp)
		if err != nil {
			return nil, err
		}
	}
	return snp, nil
}

func buildIndex(path string, snp *NamePortMapping) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		var context []byte
		context, err = ioutil.ReadFile(path)

		if err != nil {
			fmt.Println(err)
			return err
		}

		files := strings.Split(string(context), separator)
		for _, file := range files {
			if file == "\n" || file == "" {
				continue
			}

			var namespace, service string
			var mapping map[string]int32
			namespace, service, mapping, err = getNameAndPortMapping([]byte(file))
			if err != nil {
				continue
			}

			_ = snp.AddNamePortMapping(namespace, service, mapping)
		}

		return nil
	}

	dir := info.Name()
	infos, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, info := range infos {
		newPath := filepath.Join(path, info.Name())
		err := buildIndex(newPath, snp)
		if err != nil {
			return err
		}
	}
	return nil
}

func getNameAndPortMapping(context []byte) (namespace, serviceName string, mapping map[string]int32, err error) {
	mapping = make(map[string]int32)

	object, err := parseYaml(context)
	if err != nil {
		log.Printf("err while reading yaml: %v", err)
		return "", "", mapping, errors.New("err while reading yaml")
	}

	service, ok := object.(*v1.Service)
	if ok {
		serviceName = service.Name
		namespace = service.Namespace
		for _, port := range service.Spec.Ports {
			mapping[port.Name] = port.Port
		}
	} else {
		err = errors.New("object is not an service")
	}

	return namespace, serviceName, mapping, err
}

func parseYaml(content []byte) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, _, err := decode(content, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %s", err)
	}

	return obj, nil
}

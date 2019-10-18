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

var (
	mux             *sync.RWMutex
	serviceNamePort map[string]map[string]int32
)

func init() {
	serviceNamePort = make(map[string]map[string]int32)
	mux = new(sync.RWMutex)

}

func AddServiceNamePortMapping(service string, mapping map[string]int32) error {
	if len(mapping) == 0 {
		return nil
	}

	mux.Lock()
	defer mux.Unlock()

	serviceNamePort[service] = mapping
	return nil
}

func GetServicePortWithName(service, name string) (int32, error) {
	mux.RLock()
	defer mux.RUnlock()
	if port, ok := serviceNamePort[service][name]; ok {
		return port, nil
	} else {
		return 0, nil
	}
}

func BuildIndex(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}

	if !info.IsDir() {
		context, err := ioutil.ReadFile(path)

		if err != nil {
			fmt.Printf(err.Error())
			return err
		}

		files := strings.Split(string(context), separator)
		for _, file := range files {
			if file == "\n" || file == "" {
				continue
			}

			service, mapping, err := getNameAndPortMapping([]byte(file))
			if err != nil {
				continue
			}
			_ = AddServiceNamePortMapping(service, mapping)
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
		err := BuildIndex(newPath)
		if err != nil {
			return err
		}
	}
	return nil
}

func getNameAndPortMapping(context []byte) (serviceName string, mapping map[string]int32, err error) {
	mapping = make(map[string]int32)

	object, err := parseYaml([]byte(context))
	if err != nil {
		log.Printf("err while reading yaml: %v", err)
		return "", mapping, errors.New("err while reading yaml")
	}

	service, ok := object.(*v1.Service)
	if ok {
		serviceName = service.Name
		for _, port := range service.Spec.Ports {
			mapping[port.Name] = port.Port
		}

		return serviceName, mapping, nil
	} else {
		return "", mapping, errors.New("object is not an service")
	}
}

func parseYaml(content []byte) (runtime.Object, error) {
	decode := scheme.Codecs.UniversalDeserializer().Decode

	obj, _, err := decode(content, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("error while decoding YAML object. Err was: %s", err)
	}

	return obj, nil
}

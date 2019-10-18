package service

import (
	"path/filepath"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_NewNamePortMapping(t *testing.T) {
	want_snp := &NamePortMapping{
		mux:             new(sync.RWMutex),
		serviceNamePort: make(map[string]map[string]int32),
	}

	snp, err := NewNamePortMapping()
	require.NoError(t, err)
	assert.Equal(t, snp, want_snp)
}

//Test_NamePortMapping test  AddNamePortMapping and GetServicePortWithName
func Test_NamePortMapping(t *testing.T) {
	var port int32 = 80

	namespace := "testing"
	service := "test"
	portName := "http"

	mapping := make(map[string]int32)
	mapping[portName] = port

	snp, err := NewNamePortMapping()
	require.NoError(t, err)

	err = snp.AddNamePortMapping(namespace, service, mapping)
	require.NoError(t, err)

	var p int32
	p, err = snp.GetServicePortWithName(namespace, service, portName)
	require.NoError(t, err)

	require.Equal(t, p, port)
}

func Test_BuildIndex(t *testing.T) {
	var namespace = "testing"
	var service = "test"
	var portName = "http"

	var src = filepath.Join("./", "fixtures")
	var filename = "service.yml"

	var want_port int32 = 80

	testPath := []string{
		src,
		filepath.Join(src, filename),
	}

	for _, path := range testPath {
		serviceIndex, err := BuildIndex(path)
		require.NoError(t, err)

		var port int32
		port, err = serviceIndex.GetServicePortWithName(namespace, service, portName)
		require.NoError(t, err)

		require.Equal(t, port, want_port)
	}
}

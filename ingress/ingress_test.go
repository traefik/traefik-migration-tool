package ingress

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
)

var updateExpected = flag.Bool("update_expected", false, "Update expected files in testdata")

func TestIngresses(t *testing.T) {
	testCases := []struct {
		ingressFile string
		objectCount int
	}{
		{
			ingressFile: "ingress.yml",
			objectCount: 1,
		},
		{
			ingressFile: "ingress_with_protocol.yml",
			objectCount: 1,
		},
		{
			ingressFile: "ingress_with_matcher.yml",
			objectCount: 1,
		},
		{
			ingressFile: "ingress_with_matcher_modifier.yml",
			objectCount: 3,
		},
		{
			ingressFile: "ingress_with_headers_annotations.yml",
			objectCount: 2,
		},
	}

	if *updateExpected {
		outputDir := filepath.Join("fixtures", "output")
		require.NoError(t, os.RemoveAll(outputDir))
		require.NoError(t, os.MkdirAll(outputDir, 0755))
	}

	for _, test := range testCases {
		t.Run(test.ingressFile, func(t *testing.T) {
			bytes, err := ioutil.ReadFile(filepath.Join("fixtures", test.ingressFile))
			require.NoError(t, err)

			objectIngress, err := parseYaml(bytes)
			require.NoError(t, err)

			objects := convertIngress(objectIngress.(*v1beta1.Ingress))

			if !*updateExpected {
				require.Len(t, objects, test.objectCount)
			}

			for i, object := range objects {
				s, err := encodeYaml(object, v1alpha1.GroupName+groupSuffix)
				require.NoError(t, err)

				filename := fmt.Sprintf("%s_%.2d.yml", strings.TrimSuffix(filepath.Base(test.ingressFile), filepath.Ext(test.ingressFile)), i+1)
				fixtureFile := filepath.Join("fixtures", "output", filename)

				if *updateExpected {
					require.NoError(t, ioutil.WriteFile(fixtureFile, []byte(s), 0666))
				}

				file, err := ioutil.ReadFile(fixtureFile)
				require.NoError(t, err)

				assert.YAMLEq(t, string(file), s)
			}
		})
	}
}

func TestConvertFile(t *testing.T) {
	tempDir, err := ioutil.TempDir("", "convert")
	require.NoError(t, err)
	defer func() { _ = os.RemoveAll(tempDir) }()

	err = convertFile("./fixtures", tempDir, "ingress_and_service.yml")
	require.NoError(t, err)

	fileContent, err := ioutil.ReadFile(tempDir + "/ingress_and_service.yml")
	require.NoError(t, err)
	files := strings.Split(string(fileContent), "---")
	require.Len(t, files, 2)

	object, err := parseYaml([]byte(files[0]))
	require.NoError(t, err)
	require.IsType(t, &v1alpha1.IngressRoute{}, object)

	object, err = parseYaml([]byte(files[1]))
	require.NoError(t, err)
	require.IsType(t, &corev1.Service{}, object)

}

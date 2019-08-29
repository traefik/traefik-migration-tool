package ingress

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
)

func TestIngresses(t *testing.T) {
	bytes, err := ioutil.ReadFile("./fixtures/ingress.yml")
	require.NoError(t, err)

	object, err := MustParseYaml(bytes)
	require.NoError(t, err)

	objects := ConvertIngress(object.(*v1beta1.Ingress))

	expectedRoute := v1alpha1.IngressRouteSpec{
		Routes: []v1alpha1.Route{
			{
				Match: "Host(`traefik.tchouk`) && PathPrefix(`/bar`)",
				Kind:  "Rule",
				Services: []v1alpha1.Service{
					{
						Name: "service1",
						Port: 80,
					},
				},
			},
			{
				Match: "Host(`traefik.tchouk`) && PathPrefix(`/foo`)",
				Kind:  "Rule",
				Services: []v1alpha1.Service{
					{
						Name: "service1",
						Port: 80,
					},
				},
			},
		},
	}




		assert.Equal(t, expectedRoute, objects[0].(*v1alpha1.IngressRoute).Spec)
}

func TestConvertFile(t *testing.T) {
	tempDir, err := ioutil.TempDir(os.TempDir(), "convert")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	err = ConvertFile("./fixtures", tempDir, "ingress_and_service.yml")
	require.NoError(t, err)

	fileContent, err := ioutil.ReadFile(tempDir + "/ingress_and_service.yml")
	files := strings.Split(string(fileContent), "---")
	require.Len(t, files, 2)

	object, err := MustParseYaml([]byte(files[0]))
	require.NoError(t, err)
	require.IsType(t, &v1alpha1.IngressRoute{}, object)

	object, err = MustParseYaml([]byte(files[1]))
	require.NoError(t, err)
	require.IsType(t, &corev1.Service{}, object)

}

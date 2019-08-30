package ingress

import (
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/api/extensions/v1beta1"
)

func TestIngresses(t *testing.T) {
	testCases := []struct {
		desc           string
		ingressFile    string
		expectedRoutes map[string]v1alpha1.IngressRouteSpec
		expectedMiddlewares map[string]dynamic.Middleware
	}{
		{
			desc: "Simple ingress",
			ingressFile: "./fixtures/ingress.yml",
			expectedRoutes: map[string]v1alpha1.IngressRouteSpec{
				"testing.test": {
					EntryPoints: []string{"web"},
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
				},
			},
		},
		{
			desc: "Ingress with matcher",
			ingressFile: "./fixtures/ingress_with_matcher.yml",
			expectedRoutes: map[string]v1alpha1.IngressRouteSpec{
				"testing.test": {
					EntryPoints: []string{"web"},
					Routes: []v1alpha1.Route{
						{
							Match: "Host(`traefik.tchouk`) && Path(`/bar`)",
							Kind:  "Rule",
							Services: []v1alpha1.Service{
								{
									Name: "service1",
									Port: 80,
								},
							},
						},
						{
							Match: "Host(`traefik.tchouk`) && Path(`/foo`)",
							Kind:  "Rule",
							Services: []v1alpha1.Service{
								{
									Name: "service1",
									Port: 80,
								},
							},
						},
					},
				},
			},
		},
		{
			desc: "Ingress with matcher and modifier",
			ingressFile: "./fixtures/ingress_with_matcher_modifier.yml",
			expectedMiddlewares: map[string]dynamic.Middleware{
				"testing.traefik.tchouk/bar": {StripPrefix: &dynamic.StripPrefix{Prefixes: []string{"/bar"}}},
				"testing.traefik.tchouk/foo": {StripPrefix: &dynamic.StripPrefix{Prefixes: []string{"/foo"}}},
			},
			expectedRoutes: map[string]v1alpha1.IngressRouteSpec{
				"testing.test": {
					EntryPoints: []string{"web"},
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
							Middlewares:[]v1alpha1.MiddlewareRef{
								{
									Name:      "traefik.tchouk/bar",
									Namespace: "testing",
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
							Middlewares:[]v1alpha1.MiddlewareRef{
								{
									Name:      "traefik.tchouk/foo",
									Namespace: "testing",
								},
							},
						},
					},
				},
			},
		},
	}

	for _, test := range testCases {
		test := test
		t.Run(test.desc, func(t *testing.T) {
			t.Parallel()
			bytes, err := ioutil.ReadFile(test.ingressFile)
			require.NoError(t, err)

			objectIngress, err := mustParseYaml(bytes)
			require.NoError(t, err)

			objects := ConvertIngress(objectIngress.(*v1beta1.Ingress))

			require.Len(t, objects, len(test.expectedRoutes)+len(test.expectedMiddlewares))
			for _, object := range objects {
				switch o := object.(type) {
				case *v1alpha1.IngressRoute:
					key := o.Namespace + "." + o.Name
					require.Contains(t, test.expectedRoutes, key)
					assert.Equal(t, test.expectedRoutes[key], o.Spec)
				case *v1alpha1.Middleware:
					key := o.Namespace + "." + o.Name
					require.Contains(t, test.expectedMiddlewares, key)
					assert.Equal(t, test.expectedMiddlewares[key], o.Spec)
				default:
				}
			}
		})
	}


}

func TestConvertFile(t *testing.T) {
	tempDir, err := ioutil.TempDir(os.TempDir(), "convert")
	require.NoError(t, err)
	defer os.RemoveAll(tempDir)

	err = convertFile("./fixtures", tempDir, "ingress_and_service.yml")
	require.NoError(t, err)

	fileContent, err := ioutil.ReadFile(tempDir + "/ingress_and_service.yml")
	require.NoError(t, err)
	files := strings.Split(string(fileContent), "---")
	require.Len(t, files, 2)

	object, err := mustParseYaml([]byte(files[0]))
	require.NoError(t, err)
	require.IsType(t, &v1alpha1.IngressRoute{}, object)

	object, err = mustParseYaml([]byte(files[1]))
	require.NoError(t, err)
	require.IsType(t, &corev1.Service{}, object)

}

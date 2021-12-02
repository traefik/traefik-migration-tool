package ingress

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	netv1 "k8s.io/api/networking/v1"
)

var updateExpected = flag.Bool("update_expected", false, "Update expected files in testdata")

func Test_convertIngress(t *testing.T) {
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
		{
			ingressFile: "ingress_rewrite_target.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_whitelist.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_whitelist_xforwarded.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_passtlscert.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_redirect_approot.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_redirect_regex.yml",
			objectCount: 3,
		},
		// FIXME errorPages middleware
		// {
		// 	ingressFile: "ingress_with_errorpage.yml",
		// 	objectCount: 3,
		// },
		{
			ingressFile: "ingress_with_ratelimit.yml",
			objectCount: 3,
		},
		{
			ingressFile: "ingress_with_request_modifier.yml",
			objectCount: 2,
		},
	}

	outputDir := filepath.Join("fixtures", "output_convertIngress")
	if *updateExpected {
		require.NoError(t, os.RemoveAll(outputDir))
		require.NoError(t, os.MkdirAll(outputDir, 0o755))
	}

	for _, test := range testCases {
		t.Run(test.ingressFile, func(t *testing.T) {
			bytes, err := os.ReadFile(filepath.Join("fixtures", "input", test.ingressFile))
			require.NoError(t, err)

			object, err := parseYaml(bytes)
			require.NoError(t, err)

			objects := convertIngress(object.(*netv1.Ingress))

			if !*updateExpected {
				require.Len(t, objects, test.objectCount)
			}

			for i, object := range objects {
				s, err := encodeYaml(object, v1alpha1.GroupName+groupSuffix)
				require.NoError(t, err)

				filename := fmt.Sprintf("%s_%.2d.yml", strings.TrimSuffix(filepath.Base(test.ingressFile), filepath.Ext(test.ingressFile)), i+1)
				fixtureFile := filepath.Join(outputDir, filename)

				if *updateExpected {
					require.NoError(t, os.WriteFile(fixtureFile, []byte(s), 0o666))
				}

				file, err := os.ReadFile(fixtureFile)
				require.NoError(t, err)

				assert.YAMLEq(t, string(file), s)
			}
		})
	}
}

func Test_convertFile(t *testing.T) {
	tempDir := t.TempDir()

	testCases := []struct {
		ingressFile string
		objectCount int
	}{
		{
			ingressFile: "ingress.yml",
			objectCount: 1,
		},
		{
			ingressFile: "items_ingress.yml",
			objectCount: 1,
		},
		{
			ingressFile: "items_mix.yml",
			objectCount: 1,
		},
		{
			ingressFile: "ingress_extensions.yml",
			objectCount: 1,
		},
		{
			ingressFile: "ingress_networking_v1beta1.yml",
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
		{
			ingressFile: "ingress_rewrite_target.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_whitelist.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_whitelist_xforwarded.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_passtlscert.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_redirect_approot.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_redirect_regex.yml",
			objectCount: 3,
		},
		// FIXME errorPages middleware
		// {
		// 	ingressFile: "ingress_with_errorpage.yml",
		// 	objectCount: 3,
		// },
		{
			ingressFile: "ingress_with_ratelimit.yml",
			objectCount: 3,
		},
		{
			ingressFile: "ingress_with_request_modifier.yml",
			objectCount: 2,
		},
		{
			ingressFile: "ingress_with_middleware_name.yml",
			objectCount: 1,
		},
	}

	fixturesDir := filepath.Join("fixtures", "output_convertFile")
	if *updateExpected {
		require.NoError(t, os.RemoveAll(fixturesDir))
		require.NoError(t, os.MkdirAll(fixturesDir, 0o755))
	}

	for _, test := range testCases {
		t.Run(test.ingressFile, func(t *testing.T) {
			err := convertFile(filepath.Join("fixtures", "input"), tempDir, test.ingressFile)
			require.NoError(t, err)

			require.FileExists(t, filepath.Join(tempDir, test.ingressFile))

			if *updateExpected {
				var src *os.File
				src, err = os.Open(filepath.Join(tempDir, test.ingressFile))
				require.NoError(t, err)
				var dst *os.File
				dst, err = os.Create(filepath.Join(fixturesDir, test.ingressFile))
				require.NoError(t, err)
				_, err = io.Copy(dst, src)
				require.NoError(t, err)
			}

			fixture, err := os.ReadFile(filepath.Join(fixturesDir, test.ingressFile))
			require.NoError(t, err)

			output, err := os.ReadFile(filepath.Join(tempDir, test.ingressFile))
			require.NoError(t, err)

			assert.YAMLEq(t, string(fixture), string(output))
		})
	}
}

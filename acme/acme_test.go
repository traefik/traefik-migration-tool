package acme

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var updateExpected = flag.Bool("update_expected", true, "Update expected files in testdata")

func TestConvert(t *testing.T) {
	srcFile := "./fixtures/acme.json"
	fixtureFile := "./fixtures/new-acme.json"

	dir, err := ioutil.TempDir("", "traefik-migration-tool")
	require.NoError(t, err)

	defer func() { _ = os.RemoveAll(dir) }()

	dstFile := filepath.Join(dir, "new-acme.json")

	err = Convert(srcFile, dstFile)
	require.NoError(t, err)

	actual, err := ioutil.ReadFile(dstFile)
	require.NoError(t, err)

	fmt.Println(dstFile)

	if *updateExpected {
		dst, err := os.Open(dstFile)
		require.NoError(t, err)
		fixture, err := os.Create(fixtureFile)
		require.NoError(t, err)

		_, err = io.Copy(fixture, dst)
		require.NoError(t, err)
	}

	expected, err := ioutil.ReadFile(fixtureFile)
	require.NoError(t, err)

	assert.JSONEq(t, string(expected), string(actual))

}

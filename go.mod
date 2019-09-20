module github.com/containous/traefik-migration-tool

go 1.13

require (
	github.com/BurntSushi/toml v0.3.1
	github.com/containous/flaeg v1.4.1
	github.com/containous/traefik/v2 v2.0.0
	github.com/go-acme/lego/v3 v3.0.2
	github.com/mitchellh/hashstructure v1.0.0
	github.com/spf13/cobra v0.0.5
	github.com/stretchr/testify v1.4.0
	gopkg.in/yaml.v2 v2.2.2
	k8s.io/api v0.0.0-20190718183219-b59d8169aab5
	k8s.io/apimachinery v0.0.0-20190612205821-1799e75a0719
	k8s.io/client-go v0.0.0-20190718183610-8e956561bbf5
)

replace (
	github.com/Azure/go-autorest => github.com/Azure/go-autorest v12.4.1+incompatible
	github.com/docker/docker => github.com/docker/engine v0.0.0-20190725163905-fa8dd90ceb7b
)

// Waiting for the merge of https://github.com/go-acme/lego/pull/962
replace github.com/labbsr0x/goh => github.com/labbsr0x/goh v0.0.0-20190830205702-3d6988c73e10

// Containous forks
replace (
	github.com/abbot/go-http-auth => github.com/containous/go-http-auth v0.4.1-0.20180112153951-65b0cdae8d7f
	github.com/go-check/check => github.com/containous/check v0.0.0-20170915194414-ca0bf163426a
	github.com/gorilla/mux => github.com/containous/mux v0.0.0-20181024131434-c33f32e26898
	github.com/mailgun/minheap => github.com/containous/minheap v0.0.0-20190809180810-6e71eb837595
	github.com/mailgun/multibuf => github.com/containous/multibuf v0.0.0-20190809014333-8b6c9a7e6bba
	github.com/rancher/go-rancher-metadata => github.com/containous/go-rancher-metadata v0.0.0-20190402144056-c6a65f8b7a28
)

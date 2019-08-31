package ingress

import (
	"fmt"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/mitchellh/hashstructure"
	extensionsv1beta1 "k8s.io/api/extensions/v1beta1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func getHeadersMiddleware(ingress *extensionsv1beta1.Ingress) *v1alpha1.Middleware {
	headers := &dynamic.Headers{
		CustomRequestHeaders:    getMapValue(ingress.Annotations, annotationKubernetesCustomRequestHeaders),
		CustomResponseHeaders:   getMapValue(ingress.Annotations, annotationKubernetesCustomResponseHeaders),
		AllowedHosts:            getSliceStringValue(ingress.Annotations, annotationKubernetesAllowedHosts),
		HostsProxyHeaders:       getSliceStringValue(ingress.Annotations, annotationKubernetesProxyHeaders),
		SSLForceHost:            getBoolValue(ingress.Annotations, annotationKubernetesSSLForceHost, false),
		SSLRedirect:             getBoolValue(ingress.Annotations, annotationKubernetesSSLRedirect, false),
		SSLTemporaryRedirect:    getBoolValue(ingress.Annotations, annotationKubernetesSSLTemporaryRedirect, false),
		SSLHost:                 getStringValue(ingress.Annotations, annotationKubernetesSSLHost, ""),
		SSLProxyHeaders:         getMapValue(ingress.Annotations, annotationKubernetesSSLProxyHeaders),
		STSSeconds:              getInt64Value(ingress.Annotations, annotationKubernetesHSTSMaxAge, 0),
		STSIncludeSubdomains:    getBoolValue(ingress.Annotations, annotationKubernetesHSTSIncludeSubdomains, false),
		STSPreload:              getBoolValue(ingress.Annotations, annotationKubernetesHSTSPreload, false),
		ForceSTSHeader:          getBoolValue(ingress.Annotations, annotationKubernetesForceHSTSHeader, false),
		FrameDeny:               getBoolValue(ingress.Annotations, annotationKubernetesFrameDeny, false),
		CustomFrameOptionsValue: getStringValue(ingress.Annotations, annotationKubernetesCustomFrameOptionsValue, ""),
		ContentTypeNosniff:      getBoolValue(ingress.Annotations, annotationKubernetesContentTypeNosniff, false),
		BrowserXSSFilter:        getBoolValue(ingress.Annotations, annotationKubernetesBrowserXSSFilter, false),
		CustomBrowserXSSValue:   getStringValue(ingress.Annotations, annotationKubernetesCustomBrowserXSSValue, ""),
		ContentSecurityPolicy:   getStringValue(ingress.Annotations, annotationKubernetesContentSecurityPolicy, ""),
		PublicKey:               getStringValue(ingress.Annotations, annotationKubernetesPublicKey, ""),
		ReferrerPolicy:          getStringValue(ingress.Annotations, annotationKubernetesReferrerPolicy, ""),
		IsDevelopment:           getBoolValue(ingress.Annotations, annotationKubernetesIsDevelopment, false),
	}

	if !headers.HasCustomHeadersDefined() && !headers.HasCorsHeadersDefined() && !headers.HasSecureHeadersDefined() {
		return nil
	}

	hash, err := hashstructure.Hash(headers, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "headers", hash), Namespace: ingress.Namespace},
		Spec:       dynamic.Middleware{Headers: headers},
	}
}

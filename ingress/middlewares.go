package ingress

import (
	"fmt"
	"log"
	"strings"

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


func getAuthMiddleware(ingress *extensionsv1beta1.Ingress) *v1alpha1.Middleware{
	authType := getStringValue(ingress.Annotations, annotationKubernetesAuthType, "")
	if len(authType) == 0 {
		return nil
	}

	middleware := dynamic.Middleware{}

	switch strings.ToLower(authType) {
	case "basic":
		basic := getBasicAuthConfig(ingress.Annotations)
		middleware.BasicAuth = basic
	case "digest":
		digest := getDigestAuthConfig(ingress.Annotations)
		middleware.DigestAuth = digest
	case "forward":
		forward, err := getForwardAuthConfig(ingress.Annotations)
		if err != nil {
			log.Println(err)
			return nil
		}
		middleware.ForwardAuth = forward
	default:
		return nil
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "auth", hash), Namespace: ingress.Namespace},
		Spec:       middleware,
	}
}

func getBasicAuthConfig(annotations map[string]string) *dynamic.BasicAuth {

	// TODO handle secret
	// credentials, err := getAuthCredentials(i, k8sClient)
	// if err != nil {
	// 	return nil, err
	// }

	return &dynamic.BasicAuth{
		// Users:        credentials,
		RemoveHeader: getBoolValue(annotations, annotationKubernetesAuthRemoveHeader, false),
		HeaderField: getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
	}
}

func getDigestAuthConfig(annotations map[string]string) *dynamic.DigestAuth {


	// TODO handle secret
	// credentials, err := getAuthCredentials(i, k8sClient)
	// if err != nil {
	// 	return nil, err
	// }

	return &dynamic.DigestAuth{
		// Users: credentials,
		RemoveHeader: getBoolValue(annotations, annotationKubernetesAuthRemoveHeader, false),
		HeaderField: getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
	}
}

func getForwardAuthConfig(annotations map[string]string) (*dynamic.ForwardAuth, error) {
	authURL := getStringValue(annotations, annotationKubernetesAuthForwardURL, "")
	if len(authURL) == 0 {
		return nil, fmt.Errorf("forward authentication requires a url")
	}

	forwardAuth := &dynamic.ForwardAuth{
		Address:             authURL,
		TrustForwardHeader:  getBoolValue(annotations, annotationKubernetesAuthForwardTrustHeaders, false),
		AuthResponseHeaders: getSliceStringValue(annotations, annotationKubernetesAuthForwardResponseHeaders),
	}

	// TODO handle secret
	// authSecretName := getStringValue(annotations, annotationKubernetesAuthForwardTLSSecret, "")
	// if len(authSecretName) > 0 {
	// 	authSecretCert, authSecretKey, err := loadAuthTLSSecret(i.Namespace, authSecretName, k8sClient)
	// 	if err != nil {
	// 		return nil, fmt.Errorf("failed to load auth secret: %s", err)
	// 	}
	//
	// 	forwardAuth.TLS = &types.ClientTLS{
	// 		Cert:               authSecretCert,
	// 		Key:                authSecretKey,
	// 		InsecureSkipVerify: getBoolValue(annotations, annotationKubernetesAuthForwardTLSInsecure, false),
	// 	}
	// }

	return forwardAuth, nil
}

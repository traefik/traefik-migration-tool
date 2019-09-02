package ingress

import (
	"fmt"
	"log"
	"strings"

	"github.com/containous/traefik/v2/pkg/config/dynamic"
	"github.com/containous/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"github.com/mitchellh/hashstructure"
	"gopkg.in/yaml.v2"
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

func getAuthMiddleware(ingress *extensionsv1beta1.Ingress) *v1alpha1.Middleware {
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
		HeaderField:  getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
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
		HeaderField:  getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
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

func getWhiteList(i *extensionsv1beta1.Ingress) *v1alpha1.Middleware {
	ranges := getSliceStringValue(i.Annotations, annotationKubernetesWhiteListSourceRange)
	if len(ranges) <= 0 {
		return nil
	}

	middleware := dynamic.Middleware{
		IPWhiteList: &dynamic.IPWhiteList{
			SourceRange: ranges,
		},
	}

	if getBoolValue(i.Annotations, annotationKubernetesWhiteListUseXForwardedFor, false) {
		middleware.IPWhiteList.IPStrategy = &dynamic.IPStrategy{}
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "whitelist", hash), Namespace: i.Namespace},
		Spec:       middleware,
	}
}

func getPassTLSClientCert(i *extensionsv1beta1.Ingress) *v1alpha1.Middleware {
	var passTLSClientCert *TLSClientHeaders

	passRaw := getStringValue(i.Annotations, annotationKubernetesPassTLSClientCert, "")
	if len(passRaw) == 0 {
		return nil
	}

	passTLSClientCert = &TLSClientHeaders{}
	err := yaml.Unmarshal([]byte(passRaw), passTLSClientCert)
	if err != nil {
		log.Println(err)
	}

	middleware := dynamic.Middleware{
		PassTLSClientCert: passTLSClientCert.getPassTLSCert(),
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "passtlscert", hash), Namespace: i.Namespace},
		Spec:       middleware,
	}
}

// TLSClientHeaders holds the TLS client cert headers configuration.
type TLSClientHeaders struct {
	PEM   bool                       `description:"Enable header with escaped client pem" json:"pem"`
	Infos *TLSClientCertificateInfos `description:"Enable header with configured client cert infos" json:"infos,omitempty"`
}

func (t *TLSClientHeaders) getPassTLSCert() *dynamic.PassTLSClientCert {
	passTLS := &dynamic.PassTLSClientCert{
		PEM: t.PEM,
	}
	if t.Infos != nil {
		passTLS.Info = &dynamic.TLSClientCertificateInfo{
			NotAfter:  t.Infos.NotAfter,
			NotBefore: t.Infos.NotBefore,
			Sans:      t.Infos.Sans,
		}
		if t.Infos.Issuer != nil {
			passTLS.Info.Issuer = &dynamic.TLSCLientCertificateDNInfo{
				Country:         t.Infos.Issuer.Country,
				Province:        t.Infos.Issuer.Province,
				Locality:        t.Infos.Issuer.Locality,
				Organization:    t.Infos.Issuer.Organization,
				CommonName:      t.Infos.Issuer.CommonName,
				SerialNumber:    t.Infos.Issuer.SerialNumber,
				DomainComponent: t.Infos.Issuer.DomainComponent,
			}
			if t.Infos.Subject != nil {
				passTLS.Info.Subject = &dynamic.TLSCLientCertificateDNInfo{
					Country:         t.Infos.Subject.Country,
					Province:        t.Infos.Subject.Province,
					Locality:        t.Infos.Subject.Locality,
					Organization:    t.Infos.Subject.Organization,
					CommonName:      t.Infos.Subject.CommonName,
					SerialNumber:    t.Infos.Subject.SerialNumber,
					DomainComponent: t.Infos.Subject.DomainComponent,
				}
			}
		}
	}
	return passTLS
}

// TLSClientCertificateInfos holds the client TLS certificate infos configuration
type TLSClientCertificateInfos struct {
	NotAfter  bool                         `description:"Add NotAfter info in header" json:"notAfter"`
	NotBefore bool                         `description:"Add NotBefore info in header" json:"notBefore"`
	Sans      bool                         `description:"Add Sans info in header" json:"sans"`
	Subject   *TLSCLientCertificateDNInfos `description:"Add Subject info in header" json:"subject,omitempty"`
	Issuer    *TLSCLientCertificateDNInfos `description:"Add Issuer info in header" json:"issuer,omitempty"`
}

// TLSCLientCertificateDNInfos holds the client TLS certificate distinguished name infos configuration
// cf https://tools.ietf.org/html/rfc3739
type TLSCLientCertificateDNInfos struct {
	Country         bool `description:"Add Country info in header" json:"country"`
	Province        bool `description:"Add Province info in header" json:"province"`
	Locality        bool `description:"Add Locality info in header" json:"locality"`
	Organization    bool `description:"Add Organization info in header" json:"organization"`
	CommonName      bool `description:"Add CommonName info in header" json:"commonName"`
	SerialNumber    bool `description:"Add SerialNumber info in header" json:"serialNumber"`
	DomainComponent bool `description:"Add Domain Component info in header" json:"domainComponent"`
}

func getFrontendRedirect(namespace string, annotations map[string]string, baseName, path string) *v1alpha1.Middleware {
	permanent := getBoolValue(annotations, annotationKubernetesRedirectPermanent, false)

	if appRoot := getStringValue(annotations, annotationKubernetesAppRoot, ""); appRoot != "" && (path == "/" || path == "") {
		regex := fmt.Sprintf("%s$", baseName)
		if path == "" {
			regex = fmt.Sprintf("%s/$", baseName)
		}
		return getRedirectMiddleware(namespace, regex, fmt.Sprintf("%s/%s", strings.TrimRight(baseName, "/"), strings.TrimLeft(appRoot, "/")), permanent)
	}

	redirectEntryPoint := getStringValue(annotations, annotationKubernetesRedirectEntryPoint, "")
	if len(redirectEntryPoint) > 0 {
		log.Printf("EntryPoint redirect is not possible in v2")
		return nil
	}

	redirectRegex, err := getStringSafeValue(annotations, annotationKubernetesRedirectRegex, "")
	if err != nil {
		log.Printf("Skipping Redirect on Ingress due to invalid regex: %s", redirectRegex)
		return nil
	}

	redirectReplacement, err := getStringSafeValue(annotations, annotationKubernetesRedirectReplacement, "")
	if err != nil {
		log.Printf("Skipping Redirect on Ingress due to invalid replacement: %q", redirectRegex)
		return nil
	}

	if len(redirectRegex) > 0 && len(redirectReplacement) > 0 {
		return getRedirectMiddleware(namespace, redirectRegex, redirectReplacement, permanent)
	}

	return nil
}

func getRedirectMiddleware(namespace string, regex string, replacement string, permanent bool) *v1alpha1.Middleware {
	middleware := dynamic.Middleware{
		RedirectRegex: &dynamic.RedirectRegex{
			Regex:       regex,
			Replacement: replacement,
			Permanent:   permanent,
		},
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "redirect", hash), Namespace: namespace},
		Spec:       middleware,
	}
}

func getErrorPages(i *extensionsv1beta1.Ingress) []*v1alpha1.Middleware {
	var errorPages map[string]*dynamic.ErrorPage

	pagesRaw := getStringValue(i.Annotations, annotationKubernetesErrorPages, "")
	if len(pagesRaw) > 0 {
		errorPages = make(map[string]*dynamic.ErrorPage)
		err := yaml.Unmarshal([]byte(pagesRaw), errorPages)
		if err != nil {
			log.Println(err)
			return nil
		}
	}

	var mids []*v1alpha1.Middleware

	for id, errorPage := range errorPages {
		errorPageMiddleware := dynamic.Middleware{
			Errors: errorPage,
		}
		
		hash, err := hashstructure.Hash(errorPageMiddleware, nil)
		if err != nil {
			panic(err)
		}

		mids = append(mids, &v1alpha1.Middleware{
			ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%s-%d", "errorpage", id, hash), Namespace: i.Namespace},
			Spec:       errorPageMiddleware,
		})
	}

	return mids
}

// func getRateLimit(i *extensionsv1beta1.Ingress) *types.RateLimit {
// 	var rateLimit *types.RateLimit
//
// 	rateRaw := getStringValue(i.Annotations, annotationKubernetesRateLimit, "")
// 	if len(rateRaw) > 0 {
// 		rateLimit = &types.RateLimit{}
// 		err := yaml.Unmarshal([]byte(rateRaw), rateLimit)
// 		if err != nil {
// 			log.Error(err)
// 			return nil
// 		}
// 	}
//
// 	return rateLimit
// }

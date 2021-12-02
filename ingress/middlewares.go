package ingress

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/mitchellh/hashstructure"
	"github.com/traefik/traefik/v2/pkg/config/dynamic"
	"github.com/traefik/traefik/v2/pkg/provider/kubernetes/crd/traefik/v1alpha1"
	"gopkg.in/yaml.v2"
	netv1 "k8s.io/api/networking/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// Rate holds a rate limiting configuration for a specific time period.
type Rate struct {
	Period  time.Duration `json:"period,omitempty"`
	Average int64         `json:"average,omitempty"`
	Burst   int64         `json:"burst,omitempty"`
}

// RateLimit holds a rate limiting configuration for a given frontend.
type RateLimit struct {
	RateSet       map[string]*Rate `json:"rateset,omitempty"`
	ExtractorFunc string           `json:"extractorFunc,omitempty"`
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

// TLSClientCertificateInfos holds the client TLS certificate infos configuration.
type TLSClientCertificateInfos struct {
	NotAfter  bool                         `description:"Add NotAfter info in header" json:"notAfter"`
	NotBefore bool                         `description:"Add NotBefore info in header" json:"notBefore"`
	Sans      bool                         `description:"Add Sans info in header" json:"sans"`
	Subject   *TLSClientCertificateDNInfos `description:"Add Subject info in header" json:"subject,omitempty"`
	Issuer    *TLSClientCertificateDNInfos `description:"Add Issuer info in header" json:"issuer,omitempty"`
}

// TLSClientCertificateDNInfos holds the client TLS certificate distinguished name infos configuration.
// cf https://tools.ietf.org/html/rfc3739
type TLSClientCertificateDNInfos struct {
	Country         bool `description:"Add Country info in header" json:"country"`
	Province        bool `description:"Add Province info in header" json:"province"`
	Locality        bool `description:"Add Locality info in header" json:"locality"`
	Organization    bool `description:"Add Organization info in header" json:"organization"`
	CommonName      bool `description:"Add CommonName info in header" json:"commonName"`
	SerialNumber    bool `description:"Add SerialNumber info in header" json:"serialNumber"`
	DomainComponent bool `description:"Add Domain Component info in header" json:"domainComponent"`
}

func getHeadersMiddleware(ingress *netv1.Ingress) *v1alpha1.Middleware {
	annotations := ingress.GetAnnotations()

	headers := &dynamic.Headers{
		CustomRequestHeaders:    getMapValue(annotations, annotationKubernetesCustomRequestHeaders),
		CustomResponseHeaders:   getMapValue(annotations, annotationKubernetesCustomResponseHeaders),
		AllowedHosts:            getSliceStringValue(annotations, annotationKubernetesAllowedHosts),
		HostsProxyHeaders:       getSliceStringValue(annotations, annotationKubernetesProxyHeaders),
		SSLForceHost:            getBoolValue(annotations, annotationKubernetesSSLForceHost, false),
		SSLRedirect:             getBoolValue(annotations, annotationKubernetesSSLRedirect, false),
		SSLTemporaryRedirect:    getBoolValue(annotations, annotationKubernetesSSLTemporaryRedirect, false),
		SSLHost:                 getStringValue(annotations, annotationKubernetesSSLHost, ""),
		SSLProxyHeaders:         getMapValue(annotations, annotationKubernetesSSLProxyHeaders),
		STSSeconds:              getInt64Value(annotations, annotationKubernetesHSTSMaxAge, 0),
		STSIncludeSubdomains:    getBoolValue(annotations, annotationKubernetesHSTSIncludeSubdomains, false),
		STSPreload:              getBoolValue(annotations, annotationKubernetesHSTSPreload, false),
		ForceSTSHeader:          getBoolValue(annotations, annotationKubernetesForceHSTSHeader, false),
		FrameDeny:               getBoolValue(annotations, annotationKubernetesFrameDeny, false),
		CustomFrameOptionsValue: getStringValue(annotations, annotationKubernetesCustomFrameOptionsValue, ""),
		ContentTypeNosniff:      getBoolValue(annotations, annotationKubernetesContentTypeNosniff, false),
		BrowserXSSFilter:        getBoolValue(annotations, annotationKubernetesBrowserXSSFilter, false),
		CustomBrowserXSSValue:   getStringValue(annotations, annotationKubernetesCustomBrowserXSSValue, ""),
		ContentSecurityPolicy:   getStringValue(annotations, annotationKubernetesContentSecurityPolicy, ""),
		PublicKey:               getStringValue(annotations, annotationKubernetesPublicKey, ""),
		ReferrerPolicy:          getStringValue(annotations, annotationKubernetesReferrerPolicy, ""),
		IsDevelopment:           getBoolValue(annotations, annotationKubernetesIsDevelopment, false),
	}

	if !headers.HasCustomHeadersDefined() && !headers.HasCorsHeadersDefined() && !headers.HasSecureHeadersDefined() {
		return nil
	}

	hash, err := hashstructure.Hash(headers, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "headers", hash), Namespace: ingress.GetNamespace()},
		Spec:       v1alpha1.MiddlewareSpec{Headers: headers},
	}
}

func getAuthMiddleware(ingress *netv1.Ingress) *v1alpha1.Middleware {
	authType := getStringValue(ingress.GetAnnotations(), annotationKubernetesAuthType, "")
	if authType == "" {
		return nil
	}

	middleware := v1alpha1.MiddlewareSpec{}

	switch strings.ToLower(authType) {
	case "basic":
		basic := getBasicAuthConfig(ingress.GetAnnotations())
		middleware.BasicAuth = basic
	case "digest":
		digest := getDigestAuthConfig(ingress.GetAnnotations())
		middleware.DigestAuth = digest
	case "forward":
		forward, err := getForwardAuthConfig(ingress.GetAnnotations())
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
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "auth", hash), Namespace: ingress.GetNamespace()},
		Spec:       middleware,
	}
}

func getBasicAuthConfig(annotations map[string]string) *v1alpha1.BasicAuth {
	return &v1alpha1.BasicAuth{
		Secret:       getStringValue(annotations, annotationKubernetesAuthSecret, ""),
		RemoveHeader: getBoolValue(annotations, annotationKubernetesAuthRemoveHeader, false),
		HeaderField:  getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
	}
}

func getDigestAuthConfig(annotations map[string]string) *v1alpha1.DigestAuth {
	return &v1alpha1.DigestAuth{
		Secret:       getStringValue(annotations, annotationKubernetesAuthSecret, ""),
		RemoveHeader: getBoolValue(annotations, annotationKubernetesAuthRemoveHeader, false),
		HeaderField:  getStringValue(annotations, annotationKubernetesAuthHeaderField, ""),
	}
}

func getForwardAuthConfig(annotations map[string]string) (*v1alpha1.ForwardAuth, error) {
	authURL := getStringValue(annotations, annotationKubernetesAuthForwardURL, "")
	if authURL == "" {
		return nil, fmt.Errorf("forward authentication requires a url")
	}

	return &v1alpha1.ForwardAuth{
		Address:             authURL,
		TrustForwardHeader:  getBoolValue(annotations, annotationKubernetesAuthForwardTrustHeaders, false),
		AuthResponseHeaders: getSliceStringValue(annotations, annotationKubernetesAuthForwardResponseHeaders),
		TLS: &v1alpha1.ClientTLS{
			CASecret:           "",
			CAOptional:         false,
			CertSecret:         getStringValue(annotations, annotationKubernetesAuthForwardTLSSecret, ""),
			InsecureSkipVerify: getBoolValue(annotations, annotationKubernetesAuthForwardTLSInsecure, false),
		},
	}, nil
}

func getWhiteList(ingress *netv1.Ingress) *v1alpha1.Middleware {
	ranges := getSliceStringValue(ingress.GetAnnotations(), annotationKubernetesWhiteListSourceRange)
	if len(ranges) == 0 {
		return nil
	}

	middleware := v1alpha1.MiddlewareSpec{
		IPWhiteList: &dynamic.IPWhiteList{
			SourceRange: ranges,
		},
	}

	if getBoolValue(ingress.GetAnnotations(), annotationKubernetesWhiteListUseXForwardedFor, false) {
		middleware.IPWhiteList.IPStrategy = &dynamic.IPStrategy{}
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "whitelist", hash), Namespace: ingress.GetNamespace()},
		Spec:       middleware,
	}
}

func getPassTLSClientCert(ingress *netv1.Ingress) *v1alpha1.Middleware {
	var passTLSClientCert *TLSClientHeaders

	passRaw := getStringValue(ingress.GetAnnotations(), annotationKubernetesPassTLSClientCert, "")
	if passRaw == "" {
		return nil
	}

	passTLSClientCert = &TLSClientHeaders{}
	err := yaml.Unmarshal([]byte(passRaw), passTLSClientCert)
	if err != nil {
		log.Println(err)
	}

	middleware := v1alpha1.MiddlewareSpec{
		PassTLSClientCert: passTLSClientCert.getPassTLSCert(),
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "passtlscert", hash), Namespace: ingress.GetNamespace()},
		Spec:       middleware,
	}
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

func getRedirectMiddleware(namespace, regex, replacement string, permanent bool) *v1alpha1.Middleware {
	middleware := v1alpha1.MiddlewareSpec{
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

func parseRequestModifier(namespace, requestModifier string) (*v1alpha1.Middleware, error) {
	trimmedRequestModifier := strings.TrimRight(requestModifier, " :")
	if trimmedRequestModifier == "" {
		return nil, fmt.Errorf("modifier %q is empty", requestModifier)
	}

	// Split annotation to determine modifier type
	modifierParts := strings.Split(trimmedRequestModifier, ":")
	if len(modifierParts) < 2 {
		return nil, fmt.Errorf("modifier %q is missing type or value", requestModifier)
	}

	modifier := strings.TrimSpace(modifierParts[0])
	value := strings.TrimSpace(modifierParts[1])

	var middleware v1alpha1.MiddlewareSpec
	switch modifier {
	case ruleTypeAddPrefix:
		middleware = v1alpha1.MiddlewareSpec{
			AddPrefix: &dynamic.AddPrefix{Prefix: value},
		}
	case ruleTypeReplacePath:
		middleware = v1alpha1.MiddlewareSpec{
			ReplacePath: &dynamic.ReplacePath{Path: value},
		}
	case ruleTypeReplacePathRegex:
		split := strings.Split(value, " ")
		if len(split) != 2 {
			return nil, fmt.Errorf("invalid replacePathRegex syntax %s", value)
		}
		middleware = v1alpha1.MiddlewareSpec{
			ReplacePathRegex: &dynamic.ReplacePathRegex{Regex: split[0], Replacement: split[1]},
		}
	case "":
		return nil, errors.New("cannot use empty rule")
	default:
		return nil, fmt.Errorf("cannot use non-modifier rule: %q", modifier)
	}

	hash, err := hashstructure.Hash(middleware, nil)
	if err != nil {
		panic(err)
	}

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%d", "requestmodifier", hash), Namespace: namespace},
		Spec:       middleware,
	}, nil
}

func getRateLimit(ingress *netv1.Ingress) []*v1alpha1.Middleware {
	rateRaw := getStringValue(ingress.GetAnnotations(), annotationKubernetesRateLimit, "")
	if rateRaw == "" {
		return nil
	}
	rateLimit := &RateLimit{}
	err := yaml.Unmarshal([]byte(rateRaw), rateLimit)
	if err != nil {
		log.Println(err)
		return nil
	}

	var mids []*v1alpha1.Middleware
	for rateSetKey, rateSet := range rateLimit.RateSet {
		if rateSet.Period == 0 {
			continue
		}
		rateLimitMiddleware := v1alpha1.MiddlewareSpec{
			RateLimit: &v1alpha1.RateLimit{
				Average: rateSet.Average / int64(rateSet.Period/time.Second),
				Burst:   &rateSet.Burst,
			},
		}

		if rateLimit.ExtractorFunc == "request.host" {
			rateLimitMiddleware.RateLimit.SourceCriterion = &dynamic.SourceCriterion{
				RequestHost: true,
			}
		}

		if strings.HasPrefix(rateLimit.ExtractorFunc, "request.header.") {
			sourceHeader := strings.ReplaceAll(rateLimit.ExtractorFunc, "request.header.", "")
			rateLimitMiddleware.RateLimit.SourceCriterion = &dynamic.SourceCriterion{
				RequestHeaderName: sourceHeader,
			}
		}

		hash, err := hashstructure.Hash(rateLimitMiddleware, nil)
		if err != nil {
			panic(err)
		}

		mids = append(mids, &v1alpha1.Middleware{
			ObjectMeta: v1.ObjectMeta{Name: fmt.Sprintf("%s-%s-%d", "middleware", rateSetKey, hash), Namespace: ingress.GetNamespace()},
			Spec:       rateLimitMiddleware,
		})
	}

	return mids
}

func getReplacePathRegex(rule netv1.IngressRule, path netv1.HTTPIngressPath, namespace, rewriteTarget string) *v1alpha1.Middleware {
	middlewareName := "replace-path-" + rule.Host + path.Path

	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: normalizeObjectName(middlewareName), Namespace: namespace},
		Spec: v1alpha1.MiddlewareSpec{
			ReplacePathRegex: &dynamic.ReplacePathRegex{
				Regex:       fmt.Sprintf("^%s(.*)", path.Path),
				Replacement: fmt.Sprintf("%s$1", strings.TrimRight(rewriteTarget, "/")),
			},
		},
	}
}

func getStripPrefix(path netv1.HTTPIngressPath, middlewareName, namespace string) *v1alpha1.Middleware {
	return &v1alpha1.Middleware{
		ObjectMeta: v1.ObjectMeta{Name: normalizeObjectName(middlewareName), Namespace: namespace},
		Spec: v1alpha1.MiddlewareSpec{
			StripPrefix: &dynamic.StripPrefix{Prefixes: []string{path.Path}},
		},
	}
}

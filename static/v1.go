package static

import (
	"crypto/tls"

	"github.com/containous/flaeg/parse"
)

type Configuration struct {
	LifeCycle                 *LifeCycle
	GraceTimeOut              parse.Duration
	Debug                     bool
	CheckNewVersion           bool
	SendAnonymousUsage        bool
	AccessLogsFile            string
	AccessLog                 *AccessLog
	TraefikLogsFile           string
	TraefikLog                *TraefikLog
	Tracing                   *Tracing
	LogLevel                  string
	EntryPoints               *map[string]EntryPoint
	Constraints               []string
	ACME                      *ACME
	DefaultEntryPoints        []string
	ProvidersThrottleDuration parse.Duration
	MaxIdleConnsPerHost       int
	IdleTimeout               parse.Duration
	InsecureSkipVerify        bool
	RootCAs                   []string
	Retry                     *Retry
	HealthCheck               *HealthCheck
	RespondingTimeouts        *RespondingTimeouts
	ForwardingTimeouts        *ForwardingTimeouts
	AllowMinWeightZero        bool
	KeepTrailingSlash         bool
	Web                       *Web
	Docker                    *Docker
	File                      *File
	Marathon                  *Marathon
	Consul                    *Consul
	ConsulCatalog             *ConsulCatalog
	Etcd                      *Etcd
	Zookeeper                 *Zookeeper
	Boltdb                    *Boltdb
	Kubernetes                *Kubernetes
	Mesos                     *Mesos
	Eureka                    *Eureka
	ECS                       *ECS
	Rancher                   *Rancher
	DynamoDB                  *DynamoDB
	ServiceFabric             *ServiceFabric
	Rest                      *Rest
	API                       *API
	Metrics                   *Metrics
	Ping                      *Ping
	HostResolver              *HostResolver
}

type LifeCycle struct {
	RequestAcceptGraceTimeout parse.Duration
	GraceTimeOut              parse.Duration
}

type Filters struct {
	StatusCodes   []string
	RetryAttempts bool
	Duration      parse.Duration
}

type Headers struct {
	DefaultMode string
	Names       map[string]string
}

type Fields struct {
	DefaultMode string
	Names       map[string]string
	Headers     *Headers
}

type AccessLog struct {
	File          string
	Format        string
	Filters       *Filters
	Fields        *Fields
	BufferingSize int64
}

type TraefikLog struct {
	File   string
	Format string
}

type Jaeger struct {
	SamplingServerURL      string
	SamplingType           string
	SamplingParam          float64
	LocalAgentHostPort     string
	TraceContextHeaderName string
}

type Zipkin struct {
	HTTPEndpoint string
	SameSpan     bool
	ID128Bit     bool
	Debug        bool
}

type DataDog struct {
	LocalAgentHostPort         string
	GlobalTag                  string
	Debug                      bool
	PrioritySampling           bool
	TraceIDHeaderName          string
	ParentIDHeaderName         string
	SamplingPriorityHeaderName string
	BagagePrefixHeaderName     string
}

type Tracing struct {
	Backend       string
	ServiceName   string
	SpanNameLimit int
	Jaeger        *Jaeger
	Zipkin        *Zipkin
	DataDog       *DataDog
}

type Certificates struct {
	CertFile string
	KeyFile  string
}

type ClientCA struct {
	Files    []string
	Optional bool
}

type DefaultCertificate struct {
	CertFile string
	KeyFile  string
}

type TLS struct {
	MinVersion         string
	CipherSuites       []string
	Certificates       []Certificates
	ClientCAFiles      []string
	ClientCA           *ClientCA
	DefaultCertificate *DefaultCertificate
	SniStrict          bool
}

type Redirect struct {
	EntryPoint  string
	Regex       string
	Replacement string
	Permanent   bool
}

type AuthBasic struct {
	UsersFile    string
	RemoveHeader bool
}

type Digest struct {
	UsersFile    string
	RemoveHeader bool
}

type ClientTLS struct {
	Ca                 string
	CaOptional         bool
	Cert               string
	Key                string
	InsecureSkipVerify bool
}

type Forward struct {
	Address             string
	TLS                 *ClientTLS
	TrustForwardHeader  bool
	AuthResponseHeaders []string
}

type Auth struct {
	Basic       *AuthBasic
	Digest      *Digest
	Forward     *Forward
	HeaderField string
}

type WhiteList struct {
	SourceRange      []string
	UseXForwardedFor bool
}

type ProxyProtocol struct {
	Insecure   bool
	TrustedIPs []string
}

type ForwardedHeaders struct {
	Insecure   bool
	TrustedIPs []string
}

type EntryPoint struct {
	Address              string
	TLS                  *TLS
	Redirect             *Redirect
	Auth                 *Auth
	WhitelistSourceRange []string
	WhiteList            *WhiteList
	Compress             bool
	ProxyProtocol        *ProxyProtocol
	ForwardedHeaders     *ForwardedHeaders
}

type Store struct {
	Prefix string
}

type Domains struct {
	Main string
	SANs []string
}

type DNSChallenge struct {
	Provider                string
	DelayBeforeCheck        parse.Duration
	Resolvers               []string
	DisablePropagationCheck bool
}

type HTTPChallenge struct {
	EntryPoint string
}

type TLSChallenge struct{}

type ACME struct {
	Email                string
	Domains              []Domains
	Storage              string
	StorageFile          string
	OnDemand             bool
	OnHostRule           bool
	CAServer             string
	EntryPoint           string
	KeyType              string
	DNSChallenge         *DNSChallenge
	HTTPChallenge        *HTTPChallenge
	TLSChallenge         *TLSChallenge
	DNSProvider          string
	DelayDontCheckDNS    parse.Duration
	ACMELogging          bool
	OverrideCertificates bool
	TLSConfig            *tls.Config
}

type Retry struct {
	Attempts int
}

type HealthCheck struct {
	Interval parse.Duration
}

type RespondingTimeouts struct {
	ReadTimeout  parse.Duration
	WriteTimeout parse.Duration
	IdleTimeout  parse.Duration
}

type ForwardingTimeouts struct {
	DialTimeout           parse.Duration
	ResponseHeaderTimeout parse.Duration
}

type Statistics struct {
	RecentErrors int
}

type Prometheus struct {
	Buckets    []float64
	EntryPoint string
}

type Datadog struct {
	Address      string
	PushInterval string
}

type StatsD struct {
	Address      string
	PushInterval string
}

type InfluxDB struct {
	Address         string
	Protocol        string
	PushInterval    string
	Database        string
	RetentionPolicy string
}

type Metrics struct {
	Prometheus *Prometheus
	Datadog    *Datadog
	StatsD     *StatsD
	InfluxDB   *InfluxDB
}

type Web struct {
	Address    string
	CertFile   string
	KeyFile    string
	ReadOnly   bool
	Statistics *Statistics
	Metrics    *Metrics
	Path       string
	Auth       *Auth
	Debug      bool
}

type Docker struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Domain                    string
	TLS                       *ClientTLS
	ExposedByDefault          bool
	UseBindPortIP             bool
	SwarmMode                 bool
	Network                   string
	SwarmModeRefreshSeconds   int
}

type File struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Directory                 string
	TraefikFile               string
}

type Basic struct {
	HTTPBasicAuthUser string
	HTTPBasicPassword string
}

type Marathon struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Domain                    string
	ExposedByDefault          bool
	GroupsAsSubDomains        bool
	DCOSToken                 string
	MarathonLBCompatibility   bool
	FilterMarathonConstraints bool
	TLS                       *ClientTLS
	DialerTimeout             parse.Duration
	ResponseHeaderTimeout     parse.Duration
	TLSHandshakeTimeout       parse.Duration
	KeepAlive                 parse.Duration
	ForceTaskHostname         bool
	Basic                     *Basic
	RespectReadinessChecks    bool
}

type Consul struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Prefix                    string
	TLS                       *ClientTLS
	Username                  string
	Password                  string
}

type ConsulCatalog struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Domain                    string
	Stale                     bool
	ExposedByDefault          bool
	Prefix                    string
	StrictChecks              bool
	FrontEndRule              string
	TLS                       *ClientTLS
}

type Etcd struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Prefix                    string
	TLS                       *ClientTLS
	Username                  string
	Password                  string
	UseAPIV3                  bool
}

type Zookeeper struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Prefix                    string
	TLS                       *ClientTLS
	Username                  string
	Password                  string
}

type Boltdb struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Prefix                    string
	TLS                       *ClientTLS
	Username                  string
	Password                  string
}

type IngressEndpoint struct {
	IP               string
	Hostname         string
	PublishedService string
}

type Kubernetes struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Token                     string
	CertAuthFilePath          string
	DisablePassHostHeaders    bool
	EnablePassTLSCert         bool
	Namespaces                []string
	LabelSelector             string
	IngressClass              string
	IngressEndpoint           *IngressEndpoint
	ThrottleDuration          parse.Duration
}

type Mesos struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Domain                    string
	ExposedByDefault          bool
	GroupsAsSubDomains        bool
	ZkDetectionTimeout        int
	RefreshSeconds            int
	IPSources                 string
	StateTimeoutSecond        int
	Masters                   []string
}

type Eureka struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	Delay                     parse.Duration
	RefreshSeconds            parse.Duration
}

type ECS struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Domain                    string
	ExposedByDefault          bool
	RefreshSeconds            int
	Clusters                  []string
	Cluster                   string
	AutoDiscoverClusters      bool
	Region                    string
	AccessKeyID               string
	SecretAccessKey           string
}

type RancherAPI struct {
	Endpoint  string
	AccessKey string
	SecretKey string
}

type Metadata struct {
	IntervalPoll bool
	Prefix       string
}

type Rancher struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	Endpoint                  string
	AccessKey                 string
	SecretKey                 string
	API                       *RancherAPI
	Metadata                  *Metadata
	Domain                    string
	RefreshSeconds            int
	ExposedByDefault          bool
	EnableServiceHealthFilter bool
}

type DynamoDB struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	AccessKeyID               string
	RefreshSeconds            int
	Region                    string
	SecretAccessKey           string
	TableName                 string
	Endpoint                  string
}

type ServiceFabric struct {
	Watch                     bool
	Filename                  string
	Constraints               []string
	Trace                     bool
	TemplateVersion           int
	DebugLogGeneratedTemplate bool
	ClusterManagementURL      string
	APIVersion                string
	RefreshSeconds            int
	TLS                       *ClientTLS
	AppInsightsClientName     string
	AppInsightsKey            string
	AppInsightsBatchSize      int
	AppInsightsInterval       int
}

type Rest struct {
	EntryPoint string
}

type API struct {
	EntryPoint string
	Dashboard  bool
	Debug      bool
	Statistics *Statistics
}

type Ping struct {
	EntryPoint string
}

type HostResolver struct {
	CnameFlattening bool
	ResolvConfig    string
	ResolvDepth     int
}

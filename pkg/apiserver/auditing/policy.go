package auditing

import (
	"gopkg.in/yaml.v2"
	"io/ioutil"
	"k8s.io/klog"
	"os"
	"regexp"
	"strings"
)

const (
	PolicyFile = "/etc/kubesphere/auditing/auditing-policy.yaml"

	TypeConstant       = "Constant"
	TypeQueryParameter = "QueryParameter"
	TypePathParameter  = "PathParameter"
	TypeRequestBody    = "RequestBody"
	TypeResponseBody   = "ResponseBody"
)

// The formatter of value. The value will be formatted by connected all value of parts with 'Connector'.
type ValueFormatter struct {
	// +optional
	// The connector which used to connect multiple part value, default is '.'.
	Connector string `json:"connector,omitempty" yaml:"connector,omitempty"`
	// +optional
	Parts []Part `json:"parts,omitempty" yaml:"parts,omitempty"`
}

// Part defines how to generate value from url, request body or response body.
type Part struct {
	// The type of this part, supported values are:
	// Constant: a constant value
	// QueryParameter: get value from query parameter
	// PathParameter: get value from url
	// RequestBody: get value from request body
	// ResponseBody: get value from response body
	Type string `json:"type,omitempty" yaml:"type,omitempty"`
	// The key of part value. If type is RequestBody or ResponseBody, the key may have multiple parts,like 'metadata.name'.
	// It is also supports array operator, like Body[index].name if body is json array format, or items[index].name if
	// body is json object format. it can only has one array in the key. The grammar of array in the key is same as the
	// grammar of go array.
	Key string `json:"key,omitempty" yaml:"key,omitempty"`
}

type AuditPolicy struct {
	// The request path which this policy will matched.
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// The request methods which this policy will matched.
	Method []string `json:"method,omitempty" yaml:"method,omitempty"`
	// Ignore the matched request.
	Ignore    bool            `json:"ignore,omitempty" yaml:"ignore,omitempty"`
	Cluster   *ValueFormatter `json:"cluster,omitempty" yaml:"cluster,omitempty"`
	Workspace *ValueFormatter `json:"workspace,omitempty" yaml:"workspace,omitempty"`
	Namespace *ValueFormatter `json:"namespace,omitempty" yaml:"namespace,omitempty"`
	// The verb of matched request
	Verb *string `json:"verb,omitempty" yaml:"verb,omitempty"`
	// The resource of matched request
	Resource *string `json:"resource,omitempty" yaml:"resource,omitempty"`
	// The subresource of matched request
	Subresource *string `json:"subresource,omitempty" yaml:"subresource,omitempty"`
	// The resource name of matched request.
	ResourceName *ValueFormatter `json:"name,omitempty" yaml:"name,omitempty"`
}

type Policy struct {
	AuditPolicy
	compile *regexp.Regexp
}

func LoadPolicy() []Policy {

	file, err := os.Open(PolicyFile)
	if err != nil {
		klog.Errorf("open auditing config file %s error, %s", PolicyFile, err)
		return nil
	}

	bs, err := ioutil.ReadAll(file)
	if err != nil {
		klog.Errorf("read auditing config file %s error, %s", PolicyFile, err)
		return nil
	}

	var aps []AuditPolicy
	if err = yaml.Unmarshal(bs, &aps); err != nil {
		klog.Errorf("load auditing config file %s error, %s", PolicyFile, err)
		return nil
	}

	var ps []Policy
	for _, ap := range aps {

		if len(ap.Path) == 0 {
			continue
		}

		p := Policy{
			AuditPolicy: ap,
		}

		p.createCompile()
		ps = append(ps, p)
	}

	return ps
}

func (p *Policy) createCompile() {
	r, err := regexp.Compile("{(.*?)}")
	if err != nil {
		klog.Error(err)
		return
	}

	compile, err := regexp.Compile(r.ReplaceAllString(p.Path, "(.*)"))
	if err != nil {
		klog.Error(err)
		return
	}

	p.compile = compile
}

func (p *Policy) Match(method, url string) bool {

	if p.Method != nil && len(p.Method) > 0 {
		flag := false
		for _, m := range p.Method {
			if strings.ToLower(method) == strings.ToLower(m) {
				flag = true
				break
			}
		}

		if !flag {
			return false
		}
	}

	if p.compile == nil || !p.compile.MatchString(url) {
		return false
	}

	if len(strings.Split(p.Path, "/")) != len(strings.Split(urlFormat(url), "/")) {
		return false
	}

	return true
}

func urlFormat(url string) string {
	r, err := regexp.Compile("//+")
	if err != nil {
		klog.Error(err)
		return url
	}

	return r.ReplaceAllString(strings.TrimRight(url, "/"), "/")
}

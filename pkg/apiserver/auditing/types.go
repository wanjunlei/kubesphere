/*
Copyright 2020 KubeSphere Authors

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

     http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package auditing

import (
	"bufio"
	"bytes"
	"fmt"
	"github.com/google/uuid"
	json "github.com/json-iterator/go"
	"io/ioutil"
	"k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/klog"
	devopsv1alpha3 "kubesphere.io/kubesphere/pkg/apis/devops/v1alpha3"
	"kubesphere.io/kubesphere/pkg/apiserver/query"
	"kubesphere.io/kubesphere/pkg/apiserver/request"
	"kubesphere.io/kubesphere/pkg/client/listers/auditing/v1alpha1"
	"kubesphere.io/kubesphere/pkg/informers"
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha3"
	"kubesphere.io/kubesphere/pkg/models/resources/v1alpha3/devops"
	"kubesphere.io/kubesphere/pkg/utils/iputil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultWebhook       = "kube-auditing-webhook"
	DefaultCacheCapacity = 10000
	CacheTimeout         = time.Second
	SendTimeout          = time.Second * 3
	ChannelCapacity      = 10
)

type Auditing interface {
	Enabled() bool
	K8sAuditingEnabled() bool
	LogRequestObject(req *http.Request, info *request.RequestInfo) *Event
	LogResponseObject(e *Event, resp *ResponseCapture)
}

type internalEvent struct {
	// Devops project
	Devops string
	// The workspace which this audit event happened
	Workspace string
	// The cluster which this audit event happened
	Cluster string
	// Message send to user.
	Message string

	audit.Event
}

type internalEventList struct {
	Items []internalEvent
}

type object struct {
	v1.ObjectMeta `json:"metadata,omitempty" protobuf:"bytes,1,opt,name=metadata"`
}

type Event struct {
	internalEvent
	parameters   url.Values
	requestBody  []byte
	responseBody []byte
	policy       *Policy
	// Dose this request is a create request.
	create bool
}

type auditing struct {
	policies      []Policy
	webhookLister v1alpha1.WebhookLister
	devopsGetter  v1alpha3.Interface
	cache         chan *internalEventList
	backend       *Backend
}

func NewAuditing(informers informers.InformerFactory, url string, stopCh <-chan struct{}) Auditing {

	a := &auditing{
		policies:      LoadPolicy(),
		webhookLister: informers.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
		devopsGetter:  devops.New(informers.KubeSphereSharedInformerFactory()),
		cache:         make(chan *internalEventList, DefaultCacheCapacity),
	}

	a.backend = NewBackend(url, ChannelCapacity, a.cache, SendTimeout, stopCh)
	return a
}

func (a *auditing) getAuditLevel() audit.Level {
	wh, err := a.webhookLister.Get(DefaultWebhook)
	if err != nil {
		klog.V(8).Info(err)
		return audit.LevelNone
	}

	return (audit.Level)(wh.Spec.AuditLevel)
}

func (a *auditing) Enabled() bool {

	level := a.getAuditLevel()
	if level.Less(audit.LevelMetadata) {
		return false
	}
	return true
}

func (a *auditing) K8sAuditingEnabled() bool {
	wh, err := a.webhookLister.Get(DefaultWebhook)
	if err != nil {
		klog.V(8).Info(err)
		return false
	}

	return wh.Spec.K8sAuditingEnabled
}

func (a *auditing) LogRequestObject(req *http.Request, info *request.RequestInfo) *Event {

	// Ignore the dryRun k8s request.
	if info.IsKubernetesRequest {
		if len(req.URL.Query()["dryRun"]) != 0 {
			klog.V(6).Infof("ignore dryRun request %s", req.URL.Path)
			return nil
		}
	}

	var policy *Policy
	if a.policies != nil && len(a.policies) > 0 {
		for _, p := range a.policies {
			if p.Match(req.Method, info.Path) {

				if p.Ignore {
					return nil
				}

				policy = &p
				break
			}
		}
	}

	e := &Event{
		internalEvent: internalEvent{
			Devops:    info.DevOps,
			Workspace: info.Workspace,
			Cluster:   info.Cluster,
			Event: audit.Event{
				RequestURI:               info.Path,
				Verb:                     info.Verb,
				Level:                    a.getAuditLevel(),
				AuditID:                  types.UID(uuid.New().String()),
				Stage:                    audit.StageResponseComplete,
				ImpersonatedUser:         nil,
				UserAgent:                req.UserAgent(),
				RequestReceivedTimestamp: v1.NewMicroTime(time.Now()),
				Annotations:              nil,
				ObjectRef: &audit.ObjectReference{
					Resource:        info.Resource,
					Namespace:       info.Namespace,
					Name:            info.Name,
					UID:             "",
					APIGroup:        info.APIGroup,
					APIVersion:      info.APIVersion,
					ResourceVersion: info.ResourceScope,
					Subresource:     info.Subresource,
				},
			},
		},
	}

	if info.Verb == "create" {
		e.create = true
	}

	// Get the workspace which the devops project be in.
	if len(e.Devops) > 0 && len(e.Workspace) == 0 {
		res, err := a.devopsGetter.List("", query.New())
		if err != nil {
			klog.Error(err)
		}

		for _, obj := range res.Items {
			d := obj.(*devopsv1alpha3.DevOpsProject)

			if d.Name == e.Devops {
				e.Workspace = d.Labels["kubesphere.io/workspace"]
			} else if d.Status.AdminNamespace == e.Devops {
				e.Workspace = d.Labels["kubesphere.io/workspace"]
				e.Devops = d.Name
			}
		}
	}

	ips := make([]string, 1)
	ips[0] = iputil.RemoteIp(req)
	e.SourceIPs = ips

	user, ok := request.UserFrom(req.Context())
	if ok {
		e.User.Username = user.GetName()
		e.User.UID = user.GetUID()
		e.User.Groups = user.GetGroups()

		for k, v := range user.GetExtra() {
			e.User.Extra[k] = v
		}
	}

	e.policy = policy
	if policy != nil {
		if policy.Verb != nil {
			e.Verb = *policy.Verb
		}

		if policy.Resource != nil {
			e.ObjectRef.Resource = *policy.Resource
		}

		if policy.Subresource != nil {
			e.ObjectRef.Subresource = *policy.Subresource
		}

		e.parameters = req.URL.Query()
	}

	if needToCaptureRequestBody(req.ContentLength, e.Verb, e.Level, e.policy) {
		body, err := ioutil.ReadAll(req.Body)
		if err != nil {
			klog.Error(err)
			return e
		}
		_ = req.Body.Close()
		req.Body = ioutil.NopCloser(bytes.NewBuffer(body))

		if body != nil && len(body) > 0 {
			if e.Level.GreaterOrEqual(audit.LevelRequest) {
				e.RequestObject = &runtime.Unknown{Raw: body}
			}

			e.requestBody = body
		}
	}

	return e
}

func (a *auditing) LogResponseObject(e *Event, resp *ResponseCapture) {

	e.StageTimestamp = v1.NowMicro()
	e.ResponseStatus = &v1.Status{Code: int32(resp.StatusCode())}

	if needToCaptureResponseBody(e.Level, e.policy) {

		body := resp.Bytes()
		if body != nil && len(body) > 0 {
			if e.Level.GreaterOrEqual(audit.LevelRequestResponse) {
				e.ResponseObject = &runtime.Unknown{Raw: resp.Bytes()}
			}

			e.responseBody = resp.Bytes()
		}
	}

	if n, ok := e.getCluster(); ok {
		e.Cluster = n
	}

	if n, ok := e.getWorkspace(); ok {
		e.Workspace = n
	}

	if n, ok := e.getNamespace(); ok {
		e.ObjectRef.Namespace = n
	}

	if n, ok := e.getResourceName(); ok {
		e.ObjectRef.Name = n
	}

	a.cacheEvent(e.internalEvent)
}

func (a *auditing) cacheEvent(e internalEvent) {

	eventList := &internalEventList{}
	eventList.Items = append(eventList.Items, e)
	select {
	case a.cache <- eventList:
		return
	case <-time.After(CacheTimeout):
		klog.Errorf("cache audit event %s timeout", e.AuditID)
		break
	}
}

func needToCaptureRequestBody(length int64, verb string, level audit.Level, p *Policy) bool {

	if length == 0 {
		return false
	}

	if level.GreaterOrEqual(audit.LevelRequest) {
		return true
	}

	if verb == "create" {
		return true
	}

	if p == nil {
		return false
	}

	if p.ResourceName != nil && p.ResourceName.Parts != nil && len(p.ResourceName.Parts) > 0 {
		for _, part := range p.ResourceName.Parts {
			if part.Type == TypeRequestBody {
				return true
			}
		}
	}

	if p.Cluster != nil && p.Cluster.Parts != nil && len(p.Cluster.Parts) > 0 {
		for _, part := range p.Cluster.Parts {
			if part.Type == TypeRequestBody {
				return true
			}
		}
	}

	if p.Workspace != nil && p.Workspace.Parts != nil && len(p.Workspace.Parts) > 0 {
		for _, part := range p.Workspace.Parts {
			if part.Type == TypeRequestBody {
				return true
			}
		}
	}

	if p.Namespace != nil && p.Namespace.Parts != nil && len(p.Namespace.Parts) > 0 {
		for _, part := range p.Namespace.Parts {
			if part.Type == TypeRequestBody {
				return true
			}
		}
	}

	return false
}

func needToCaptureResponseBody(level audit.Level, p *Policy) bool {

	if level.GreaterOrEqual(audit.LevelRequestResponse) {
		return true
	}

	if p == nil {
		return false
	}

	if p.ResourceName != nil && p.ResourceName.Parts != nil && len(p.ResourceName.Parts) > 0 {
		for _, part := range p.ResourceName.Parts {
			if part.Type == TypeResponseBody {
				return true
			}
		}
	}

	if p.Cluster != nil && p.Cluster.Parts != nil && len(p.Cluster.Parts) > 0 {
		for _, part := range p.Cluster.Parts {
			if part.Type == TypeResponseBody {
				return true
			}
		}
	}

	if p.Workspace != nil && p.Workspace.Parts != nil && len(p.Workspace.Parts) > 0 {
		for _, part := range p.Workspace.Parts {
			if part.Type == TypeResponseBody {
				return true
			}
		}
	}

	if p.Namespace != nil && p.Namespace.Parts != nil && len(p.Namespace.Parts) > 0 {
		for _, part := range p.Namespace.Parts {
			if part.Type == TypeResponseBody {
				return true
			}
		}
	}

	return false
}

func (e *Event) getCluster() (string, bool) {

	if e.policy == nil || e.policy.Cluster == nil || e.policy.Cluster.Parts == nil || len(e.policy.Cluster.Parts) == 0 {

		return "", false
	}

	return e.getValue(e.policy.Cluster)
}

func (e *Event) getWorkspace() (string, bool) {
	if e.policy == nil || e.policy.Workspace == nil || e.policy.Workspace.Parts == nil || len(e.policy.Workspace.Parts) == 0 {

		return "", false
	}

	return e.getValue(e.policy.Workspace)
}

func (e *Event) getNamespace() (string, bool) {
	if e.policy == nil || e.policy.Namespace == nil || e.policy.Namespace.Parts == nil || len(e.policy.Namespace.Parts) == 0 {

		return "", false
	}

	return e.getValue(e.policy.Namespace)
}

func (e *Event) getResourceName() (string, bool) {

	if e.policy == nil || e.policy.ResourceName == nil || e.policy.ResourceName.Parts == nil || len(e.policy.ResourceName.Parts) == 0 {
		// For resource creating request, get resource name from the request body.
		if e.create && e.requestBody != nil && len(e.requestBody) > 0 {
			obj := &object{}
			if err := json.Unmarshal(e.requestBody, obj); err == nil {
				return obj.Name, true
			}
		}

		return "", false
	}

	return e.getValue(e.policy.ResourceName)
}

func (e *Event) getValue(formatter *ValueFormatter) (string, bool) {

	connector := formatter.Connector
	if len(connector) == 0 {
		connector = "."
	}

	value := ""
	for _, part := range formatter.Parts {
		v := ""
		ok := false
		switch part.Type {
		case TypeConstant:
			v = part.Key
			ok = true
		case TypeQueryParameter:
			v, ok = getValueFromQueryParameter(e.parameters, part.Key)
		case TypePathParameter:
			v, ok = getValueFromURI(e.policy.Path, e.RequestURI, part.Key)
		case TypeRequestBody:
			v, ok = getValueFromBody(e.requestBody, part.Key, e.policy.ResourceName.Connector)
		case TypeResponseBody:
			v, ok = getValueFromBody(e.responseBody, part.Key, e.policy.ResourceName.Connector)
		}

		if !ok {
			return "", false
		}

		value = value + connector + v
	}

	return strings.TrimLeft(value, connector), true

}

func getValueFromQueryParameter(parameters url.Values, key string) (string, bool) {
	if parameters != nil {
		value := parameters[key]
		if value != nil && len(value) > 0 {
			return value[0], true
		}
	}

	return "", false
}

func getValueFromURI(path, url, key string) (string, bool) {

	pathArray := strings.Split(path, "/")
	urlArray := strings.Split(url, "/")

	key = "{" + key + "}"
	for index, v := range pathArray {
		if v == key && index < len(urlArray) {
			return urlArray[index], true
		}
	}

	return "", false
}

func getValueFromBody(body []byte, key, connector string) (string, bool) {

	if body == nil || len(body) == 0 {
		klog.V(8).Info("body is empty")
		return "", false
	}

	if strings.Contains(key, "[") {
		arrayName, valueName, start, end, err := parseKeyIncludeArray(key)
		if err != nil {
			klog.V(8).Info(err)
			return "", false
		}

		var array []map[string]interface{}
		if len(arrayName) == 0 {
			array = toArray(body)
			if array == nil {
				return "", false
			}
		} else {
			m := toMap(body)
			if m == nil {
				return "", false
			}

			val, ok := m[arrayName]
			if !ok {
				return "", false
			}

			array = interfaceToArray(val)
			if array == nil {
				return "", false
			}
		}

		if end == -1 {
			end = len(array)
		}

		value := ""
		for i := start; i < end; i++ {
			fm := flatten(array[i])
			v, ok := fm[valueName]
			if !ok {
				klog.V(8).Infof("key(%s) is not exist", valueName)
				return "", false
			}

			value = value + connector + fmt.Sprintf("%v", v)
		}

		return strings.TrimLeft(value, connector), true
	} else {
		m := toMap(body)
		if m == nil {
			return "", false
		}

		if v, ok := m[key]; ok {
			return fmt.Sprintf("%v", v), true
		}

		return "", false
	}
}

// parse the key which include array, return array name, key of value and range.
// For example, the key a.b[1:3].c.d will return a.b, c.d, 1, 3, nil
func parseKeyIncludeArray(key string) (string, string, int, int, error) {

	startIndex := strings.Index(key, "[")
	endIndex := strings.Index(key, "]")
	if startIndex < 0 || endIndex < 0 {
		return "", "", 0, 0, fmt.Errorf("wrong format of key %s", key)
	}

	valueName := key[endIndex+2:]
	arrayName := key[0:startIndex]
	// If the array name is 'Body', it means the body is json array format.
	if arrayName == "Body" {
		arrayName = ""
	}

	rangeString := key[startIndex+1 : endIndex]
	var start, end int
	if strings.Contains(rangeString, ":") {
		rangeArray := strings.Split(rangeString, ":")
		if len(rangeArray[0]) == 0 {
			start = 0
		} else {
			i, err := strconv.ParseInt(rangeArray[0], 0, 32)
			if err != nil {
				return "", "", 0, 0, err
			}

			start = int(i)
		}

		if len(rangeArray[1]) == 0 {
			end = -1
		} else {
			i, err := strconv.ParseInt(rangeArray[1], 0, 32)
			if err != nil {
				return "", "", 0, 0, err
			}

			end = int(i)
		}
	} else {
		i, err := strconv.ParseInt(rangeString, 0, 32)
		if err != nil {
			return "", "", 0, 0, err
		}

		start = int(i)
		end = start + 1
	}

	return arrayName, valueName, start, end, nil
}

// Flatten takes a map and returns a new one where nested maps are replaced
// by dot-delimited keys.
func flatten(m map[string]interface{}) map[string]interface{} {

	o := make(map[string]interface{})
	for k, v := range m {
		switch child := v.(type) {
		case map[string]interface{}:
			nm := flatten(child)
			for nk, nv := range nm {
				o[k+"."+nk] = nv
			}
		default:
			o[k] = v
		}
	}
	return o
}

func toArray(bs []byte) []map[string]interface{} {
	var array []map[string]interface{}
	err := json.Unmarshal(bs, &array)
	if err != nil {
		klog.V(8).Info(err)
		return nil
	}

	return array
}

func toMap(bs []byte) map[string]interface{} {
	m := make(map[string]interface{})
	err := json.Unmarshal(bs, &m)
	if err != nil {
		klog.V(8).Info(err)
		return nil
	}

	return flatten(m)
}

func interfaceToArray(v interface{}) []map[string]interface{} {
	bs, err := json.Marshal(v)
	if err != nil {
		klog.V(8).Info(err)
		return nil
	}

	return toArray(bs)
}

type ResponseCapture struct {
	http.ResponseWriter
	wroteHeader bool
	status      int
	body        *bytes.Buffer
}

func NewResponseCapture(w http.ResponseWriter) *ResponseCapture {
	return &ResponseCapture{
		ResponseWriter: w,
		wroteHeader:    false,
		body:           new(bytes.Buffer),
	}
}

func (c *ResponseCapture) Header() http.Header {
	return c.ResponseWriter.Header()
}

func (c *ResponseCapture) Write(data []byte) (int, error) {

	c.WriteHeader(http.StatusOK)
	c.body.Write(data)
	return c.ResponseWriter.Write(data)
}

func (c *ResponseCapture) WriteHeader(statusCode int) {
	if !c.wroteHeader {
		c.status = statusCode
		c.ResponseWriter.WriteHeader(statusCode)
		c.wroteHeader = true
	}
}

func (c *ResponseCapture) Bytes() []byte {
	if c.body != nil {
		return c.body.Bytes()
	}

	return nil
}

func (c *ResponseCapture) StatusCode() int {
	return c.status
}

// Hijack implements the http.Hijacker interface.  This expands
// the Response to fulfill http.Hijacker if the underlying
// http.ResponseWriter supports it.
func (c *ResponseCapture) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	hijacker, ok := c.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("ResponseWriter doesn't support Hijacker interface")
	}
	return hijacker.Hijack()
}

// CloseNotify is part of http.CloseNotifier interface
func (c *ResponseCapture) CloseNotify() <-chan bool {
	return c.ResponseWriter.(http.CloseNotifier).CloseNotify()
}

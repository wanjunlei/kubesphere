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
	"encoding/json"
	"github.com/stretchr/testify/assert"
	"k8s.io/api/auditregistration/v1alpha1"
	"k8s.io/api/authentication/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apiserver/pkg/apis/audit"
	"k8s.io/apiserver/pkg/authentication/user"
	k8srequest "k8s.io/apiserver/pkg/endpoints/request"
	auditingv1alpha1 "kubesphere.io/kubesphere/pkg/apis/auditing/v1alpha1"
	"kubesphere.io/kubesphere/pkg/apiserver/request"
	"kubesphere.io/kubesphere/pkg/client/clientset/versioned/fake"
	"kubesphere.io/kubesphere/pkg/informers"
	"kubesphere.io/kubesphere/pkg/utils/iputil"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func TestGetAuditLevel(t *testing.T) {
	webhook := &auditingv1alpha1.Webhook{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auditingv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-auditing-webhook",
		},
		Spec: auditingv1alpha1.WebhookSpec{
			AuditLevel: v1alpha1.LevelRequestResponse,
		},
	}

	ksClient := fake.NewSimpleClientset()
	fakeInformerFactory := informers.NewInformerFactories(nil, ksClient, nil, nil, nil, nil)

	a := auditing{
		webhookLister: fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
	}

	err := fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Informer().GetIndexer().Add(webhook)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, string(webhook.Spec.AuditLevel), string(a.getAuditLevel()))
}

func TestAuditing_Enabled(t *testing.T) {
	webhook := &auditingv1alpha1.Webhook{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auditingv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-auditing-webhook",
		},
		Spec: auditingv1alpha1.WebhookSpec{
			AuditLevel: v1alpha1.LevelNone,
		},
	}

	ksClient := fake.NewSimpleClientset()
	fakeInformerFactory := informers.NewInformerFactories(nil, ksClient, nil, nil, nil, nil)

	a := auditing{
		webhookLister: fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
	}

	err := fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Informer().GetIndexer().Add(webhook)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, false, a.Enabled())
}

func TestAuditing_K8sAuditingEnabled(t *testing.T) {
	webhook := &auditingv1alpha1.Webhook{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auditingv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-auditing-webhook",
		},
		Spec: auditingv1alpha1.WebhookSpec{
			AuditLevel:         v1alpha1.LevelNone,
			K8sAuditingEnabled: true,
		},
	}

	ksClient := fake.NewSimpleClientset()
	fakeInformerFactory := informers.NewInformerFactories(nil, ksClient, nil, nil, nil, nil)

	a := auditing{
		webhookLister: fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
	}

	err := fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Informer().GetIndexer().Add(webhook)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, true, a.K8sAuditingEnabled())
}

func TestAuditing_LogRequestObject(t *testing.T) {
	webhook := &auditingv1alpha1.Webhook{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auditingv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-auditing-webhook",
		},
		Spec: auditingv1alpha1.WebhookSpec{
			AuditLevel:         v1alpha1.LevelMetadata,
			K8sAuditingEnabled: true,
		},
	}

	ksClient := fake.NewSimpleClientset()
	fakeInformerFactory := informers.NewInformerFactories(nil, ksClient, nil, nil, nil, nil)

	a := auditing{
		webhookLister: fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
	}

	err := fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Informer().GetIndexer().Add(webhook)
	if err != nil {
		panic(err)
	}

	req := &http.Request{}
	u, err := url.Parse("http://139.198.121.143:32306//kapis/tenant.kubesphere.io/v1alpha2/workspaces")
	if err != nil {
		panic(err)
	}

	req.URL = u
	req.Header = http.Header{}
	req.Header.Add(iputil.XClientIP, "192.168.0.2")
	req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
		Name: "admin",
		Groups: []string{
			"system",
		},
	}))

	info := &request.RequestInfo{
		RequestInfo: &k8srequest.RequestInfo{
			IsResourceRequest: false,
			Path:              "/kapis/tenant.kubesphere.io/v1alpha2/workspaces",
			Verb:              "get",
			APIGroup:          "tenant.kubesphere.io",
			APIVersion:        "v1alpha2",
			Resource:          "workspaces",
			Name:              "test",
		},
	}

	e := a.LogRequestObject(req, info)

	expectedEvent := &Event{
		internalEvent: internalEvent{
			Event: audit.Event{
				AuditID: e.AuditID,
				Level:   "Metadata",
				Verb:    "get",
				Stage:   "ResponseComplete",
				User: v1.UserInfo{
					Username: "admin",
					Groups: []string{
						"system",
					},
				},
				SourceIPs: []string{
					"192.168.0.2",
				},
				RequestURI:               "/kapis/tenant.kubesphere.io/v1alpha2/workspaces",
				RequestReceivedTimestamp: e.RequestReceivedTimestamp,
				ObjectRef: &audit.ObjectReference{
					Resource:        "workspaces",
					Namespace:       "",
					Name:            "test",
					UID:             "",
					APIGroup:        "tenant.kubesphere.io",
					APIVersion:      "v1alpha2",
					ResourceVersion: "",
					Subresource:     "",
				},
			},
		},
	}

	assert.Equal(t, expectedEvent, e)
}

func TestAuditing_LogResponseObject(t *testing.T) {
	webhook := &auditingv1alpha1.Webhook{
		TypeMeta: metav1.TypeMeta{
			APIVersion: auditingv1alpha1.SchemeGroupVersion.String(),
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: "kube-auditing-webhook",
		},
		Spec: auditingv1alpha1.WebhookSpec{
			AuditLevel:         v1alpha1.LevelMetadata,
			K8sAuditingEnabled: true,
		},
	}

	ksClient := fake.NewSimpleClientset()
	fakeInformerFactory := informers.NewInformerFactories(nil, ksClient, nil, nil, nil, nil)

	a := auditing{
		webhookLister: fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Lister(),
	}

	err := fakeInformerFactory.KubeSphereSharedInformerFactory().Auditing().V1alpha1().Webhooks().Informer().GetIndexer().Add(webhook)
	if err != nil {
		panic(err)
	}

	req := &http.Request{}
	u, err := url.Parse("http://139.198.121.143:32306//kapis/tenant.kubesphere.io/v1alpha2/workspaces")
	if err != nil {
		panic(err)
	}

	req.URL = u
	req.Header = http.Header{}
	req.Header.Add(iputil.XClientIP, "192.168.0.2")
	req = req.WithContext(request.WithUser(req.Context(), &user.DefaultInfo{
		Name: "admin",
		Groups: []string{
			"system",
		},
	}))

	info := &request.RequestInfo{
		RequestInfo: &k8srequest.RequestInfo{
			IsResourceRequest: false,
			Path:              "/kapis/tenant.kubesphere.io/v1alpha2/workspaces",
			Verb:              "get",
			APIGroup:          "tenant.kubesphere.io",
			APIVersion:        "v1alpha2",
			Resource:          "workspaces",
			Name:              "test",
		},
	}

	e := a.LogRequestObject(req, info)

	resp := NewResponseCapture(httptest.NewRecorder())
	resp.WriteHeader(200)

	a.LogResponseObject(e, resp)

	expectedEvent := &Event{
		internalEvent: internalEvent{
			Event: audit.Event{
				Verb:    "get",
				AuditID: e.AuditID,
				Level:   "Metadata",
				Stage:   "ResponseComplete",
				User: v1.UserInfo{
					Username: "admin",
					Groups: []string{
						"system",
					},
				},
				SourceIPs: []string{
					"192.168.0.2",
				},
				ObjectRef: &audit.ObjectReference{
					Resource:   "workspaces",
					Name:       "test",
					APIGroup:   "tenant.kubesphere.io",
					APIVersion: "v1alpha2",
				},

				RequestReceivedTimestamp: e.RequestReceivedTimestamp,
				StageTimestamp:           e.StageTimestamp,
				RequestURI:               "/kapis/tenant.kubesphere.io/v1alpha2/workspaces",
				ResponseStatus: &metav1.Status{
					Code: 200,
				},
			},
		},
	}

	expectedBs, err := json.Marshal(expectedEvent)
	if err != nil {
		panic(err)
	}
	bs, err := json.Marshal(e)
	if err != nil {
		panic(err)
	}

	assert.EqualValues(t, string(expectedBs), string(bs))
}

func TestResponseCapture_WriteHeader(t *testing.T) {
	record := httptest.NewRecorder()
	resp := NewResponseCapture(record)

	resp.WriteHeader(404)

	assert.EqualValues(t, 404, resp.StatusCode())
	assert.EqualValues(t, 404, record.Code)
}

func TestResponseCapture_Write(t *testing.T) {

	record := httptest.NewRecorder()
	resp := NewResponseCapture(record)

	body := []byte("123")

	_, err := resp.Write(body)
	if err != nil {
		panic(err)
	}

	assert.EqualValues(t, body, resp.Bytes())
	assert.EqualValues(t, body, record.Body.Bytes())
}

func TestNeedToCaptureRequestBody(t *testing.T) {

	p := &Policy{
		AuditPolicy: AuditPolicy{
			ResourceName: &ValueFormatter{
				Parts: []Part{
					{
						Type: TypeRequestBody,
					},
				},
			},
		},
	}

	assert.EqualValues(t, true, needToCaptureRequestBody(1, "create", audit.LevelMetadata, p))
	assert.EqualValues(t, true, needToCaptureRequestBody(1, "get", audit.LevelMetadata, p))
	assert.EqualValues(t, true, needToCaptureRequestBody(1, "get", audit.LevelRequest, nil))
	assert.EqualValues(t, false, needToCaptureRequestBody(0, "get", audit.LevelMetadata, nil))
}

func TestNeedToCaptureResponseBody(t *testing.T) {

	p := &Policy{
		AuditPolicy: AuditPolicy{
			ResourceName: &ValueFormatter{
				Parts: []Part{
					{
						Type: TypeResponseBody,
					},
				},
			},
		},
	}

	assert.EqualValues(t, true, needToCaptureResponseBody(audit.LevelRequest, p))
	assert.EqualValues(t, true, needToCaptureResponseBody(audit.LevelRequestResponse, nil))
	assert.EqualValues(t, true, needToCaptureResponseBody(audit.LevelRequestResponse, p))
	assert.EqualValues(t, false, needToCaptureResponseBody(audit.LevelRequest, nil))
}

func TestGetValue(t *testing.T) {

	p := &Policy{
		AuditPolicy: AuditPolicy{
			Path: "/kapis/auditing.kubesphere.io/namespaces/{namespace}/pod",
			ResourceName: &ValueFormatter{
				Connector: ",",
				Parts: []Part{
					{
						Type: TypePathParameter,
						Key:  "namespace",
					},
					{
						Type: TypeRequestBody,
						Key:  "spec.containers[1:3].name",
					},
					{
						Type: TypeResponseBody,
						Key:  "status.code",
					},
				},
			},
		},
	}

	requestBody := "{" +
		"    \"metadata\":{" +
		"        \"name\":\"ks-apiserver\"," +
		"        \"namespace\":\"kubesphere-system\"" +
		"    },\n    \"spec\":{" +
		"        \"containers\":[" +
		"            {" +
		"                \"name\":\"ks-apiserver\"" +
		"            }," +
		"            {" +
		"                \"name\":\"ks-console\"" +
		"            }," +
		"           {" +
		"                \"name\":\"redis\"" +
		"            }," +
		"            {" +
		"                \"name\":\"open-ldap\"" +
		"            }" +
		"        ]" +
		"    }" +
		"}"

	responseBody := "{" +
		"    \"message\":\"success\"," +
		"    \"status\":{" +
		"        \"code\":200" +
		"   }" +
		"}"

	e := &Event{
		requestBody:  []byte(requestBody),
		responseBody: []byte(responseBody),
		policy:       p,
	}
	e.RequestURI = "/kapis/auditing.kubesphere.io/namespaces/test/pod"

	value, _ := e.getResourceName()
	assert.EqualValues(t, "test,ks-console,redis,200", value)

	p = &Policy{
		AuditPolicy: AuditPolicy{
			ResourceName: &ValueFormatter{
				Connector: ".",
				Parts: []Part{
					{
						Type: TypeRequestBody,
						Key:  "spec.containers[1:].name",
					},
				},
			},
		},
	}

	e.policy = p
	value, _ = e.getResourceName()
	assert.EqualValues(t, "ks-console.redis.open-ldap", value)

	p = &Policy{
		AuditPolicy: AuditPolicy{
			ResourceName: &ValueFormatter{
				Connector: ".",
				Parts: []Part{
					{
						Type: TypeRequestBody,
						Key:  "spec.containers[:4].name",
					},
				},
			},
		},
	}

	e.policy = p
	value, _ = e.getResourceName()
	assert.EqualValues(t, "ks-apiserver.ks-console.redis.open-ldap", value)

	p = &Policy{
		AuditPolicy: AuditPolicy{
			ResourceName: &ValueFormatter{
				Connector: ".",
				Parts: []Part{
					{
						Type: TypeRequestBody,
						Key:  "spec.containers[2].name",
					},
				},
			},
		},
	}

	e.policy = p
	value, _ = e.getResourceName()
	assert.EqualValues(t, "redis", value)

	e.policy = nil
	e.create = true
	value, _ = e.getResourceName()
	assert.EqualValues(t, "ks-apiserver", value)
}

func TestPolicy_Match(t *testing.T) {

	p := &Policy{
		AuditPolicy: AuditPolicy{
			Path: "/devops/{devops}/pipelines/{pipeline}/runs/{run}/stop",
			Method: []string{
				"post",
			},
		},
	}

	p.createCompile()

	assert.EqualValues(t, true, p.Match("post", "////devops///devops///pipelines///pipeline////runs/run////stop////"))
	assert.EqualValues(t, false, p.Match("post", "/devops/devops/pipelines/pipeline/runs"))
	assert.EqualValues(t, false, p.Match("post", "/devops/devops/pipelines/pipeline/runs/run/nodes/node/steps/step"))
}

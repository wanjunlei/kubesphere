/*
Copyright 2020 The KubeSphere Authors.

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

// Code generated by client-gen. DO NOT EDIT.

package fake

import (
	"context"

	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	labels "k8s.io/apimachinery/pkg/labels"
	schema "k8s.io/apimachinery/pkg/runtime/schema"
	types "k8s.io/apimachinery/pkg/types"
	watch "k8s.io/apimachinery/pkg/watch"
	testing "k8s.io/client-go/testing"
	v2 "kubesphere.io/kubesphere/pkg/apis/notification/v2"
)

// FakeWebhookConfigs implements WebhookConfigInterface
type FakeWebhookConfigs struct {
	Fake *FakeNotificationV2
}

var webhookconfigsResource = schema.GroupVersionResource{Group: "notification.kubesphere.io", Version: "v2", Resource: "webhookconfigs"}

var webhookconfigsKind = schema.GroupVersionKind{Group: "notification.kubesphere.io", Version: "v2", Kind: "WebhookConfig"}

// Get takes name of the webhookConfig, and returns the corresponding webhookConfig object, and an error if there is any.
func (c *FakeWebhookConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.WebhookConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(webhookconfigsResource, name), &v2.WebhookConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.WebhookConfig), err
}

// List takes label and field selectors, and returns the list of WebhookConfigs that match those selectors.
func (c *FakeWebhookConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v2.WebhookConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(webhookconfigsResource, webhookconfigsKind, opts), &v2.WebhookConfigList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2.WebhookConfigList{ListMeta: obj.(*v2.WebhookConfigList).ListMeta}
	for _, item := range obj.(*v2.WebhookConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested webhookConfigs.
func (c *FakeWebhookConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(webhookconfigsResource, opts))
}

// Create takes the representation of a webhookConfig and creates it.  Returns the server's representation of the webhookConfig, and an error, if there is any.
func (c *FakeWebhookConfigs) Create(ctx context.Context, webhookConfig *v2.WebhookConfig, opts v1.CreateOptions) (result *v2.WebhookConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(webhookconfigsResource, webhookConfig), &v2.WebhookConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.WebhookConfig), err
}

// Update takes the representation of a webhookConfig and updates it. Returns the server's representation of the webhookConfig, and an error, if there is any.
func (c *FakeWebhookConfigs) Update(ctx context.Context, webhookConfig *v2.WebhookConfig, opts v1.UpdateOptions) (result *v2.WebhookConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(webhookconfigsResource, webhookConfig), &v2.WebhookConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.WebhookConfig), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeWebhookConfigs) UpdateStatus(ctx context.Context, webhookConfig *v2.WebhookConfig, opts v1.UpdateOptions) (*v2.WebhookConfig, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(webhookconfigsResource, "status", webhookConfig), &v2.WebhookConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.WebhookConfig), err
}

// Delete takes name of the webhookConfig and deletes it. Returns an error if one occurs.
func (c *FakeWebhookConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(webhookconfigsResource, name), &v2.WebhookConfig{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeWebhookConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(webhookconfigsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v2.WebhookConfigList{})
	return err
}

// Patch applies the patch and returns the patched webhookConfig.
func (c *FakeWebhookConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.WebhookConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(webhookconfigsResource, name, pt, data, subresources...), &v2.WebhookConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.WebhookConfig), err
}

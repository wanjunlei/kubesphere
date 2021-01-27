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

// FakeSlackConfigs implements SlackConfigInterface
type FakeSlackConfigs struct {
	Fake *FakeNotificationV2
}

var slackconfigsResource = schema.GroupVersionResource{Group: "notification.kubesphere.io", Version: "v2", Resource: "slackconfigs"}

var slackconfigsKind = schema.GroupVersionKind{Group: "notification.kubesphere.io", Version: "v2", Kind: "SlackConfig"}

// Get takes name of the slackConfig, and returns the corresponding slackConfig object, and an error if there is any.
func (c *FakeSlackConfigs) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.SlackConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(slackconfigsResource, name), &v2.SlackConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackConfig), err
}

// List takes label and field selectors, and returns the list of SlackConfigs that match those selectors.
func (c *FakeSlackConfigs) List(ctx context.Context, opts v1.ListOptions) (result *v2.SlackConfigList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(slackconfigsResource, slackconfigsKind, opts), &v2.SlackConfigList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2.SlackConfigList{ListMeta: obj.(*v2.SlackConfigList).ListMeta}
	for _, item := range obj.(*v2.SlackConfigList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested slackConfigs.
func (c *FakeSlackConfigs) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(slackconfigsResource, opts))
}

// Create takes the representation of a slackConfig and creates it.  Returns the server's representation of the slackConfig, and an error, if there is any.
func (c *FakeSlackConfigs) Create(ctx context.Context, slackConfig *v2.SlackConfig, opts v1.CreateOptions) (result *v2.SlackConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(slackconfigsResource, slackConfig), &v2.SlackConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackConfig), err
}

// Update takes the representation of a slackConfig and updates it. Returns the server's representation of the slackConfig, and an error, if there is any.
func (c *FakeSlackConfigs) Update(ctx context.Context, slackConfig *v2.SlackConfig, opts v1.UpdateOptions) (result *v2.SlackConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(slackconfigsResource, slackConfig), &v2.SlackConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackConfig), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeSlackConfigs) UpdateStatus(ctx context.Context, slackConfig *v2.SlackConfig, opts v1.UpdateOptions) (*v2.SlackConfig, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(slackconfigsResource, "status", slackConfig), &v2.SlackConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackConfig), err
}

// Delete takes name of the slackConfig and deletes it. Returns an error if one occurs.
func (c *FakeSlackConfigs) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(slackconfigsResource, name), &v2.SlackConfig{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSlackConfigs) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(slackconfigsResource, listOpts)

	_, err := c.Fake.Invokes(action, &v2.SlackConfigList{})
	return err
}

// Patch applies the patch and returns the patched slackConfig.
func (c *FakeSlackConfigs) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.SlackConfig, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(slackconfigsResource, name, pt, data, subresources...), &v2.SlackConfig{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackConfig), err
}

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

// FakeSlackReceivers implements SlackReceiverInterface
type FakeSlackReceivers struct {
	Fake *FakeNotificationV2
}

var slackreceiversResource = schema.GroupVersionResource{Group: "notification.kubesphere.io", Version: "v2", Resource: "slackreceivers"}

var slackreceiversKind = schema.GroupVersionKind{Group: "notification.kubesphere.io", Version: "v2", Kind: "SlackReceiver"}

// Get takes name of the slackReceiver, and returns the corresponding slackReceiver object, and an error if there is any.
func (c *FakeSlackReceivers) Get(ctx context.Context, name string, options v1.GetOptions) (result *v2.SlackReceiver, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootGetAction(slackreceiversResource, name), &v2.SlackReceiver{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackReceiver), err
}

// List takes label and field selectors, and returns the list of SlackReceivers that match those selectors.
func (c *FakeSlackReceivers) List(ctx context.Context, opts v1.ListOptions) (result *v2.SlackReceiverList, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootListAction(slackreceiversResource, slackreceiversKind, opts), &v2.SlackReceiverList{})
	if obj == nil {
		return nil, err
	}

	label, _, _ := testing.ExtractFromListOptions(opts)
	if label == nil {
		label = labels.Everything()
	}
	list := &v2.SlackReceiverList{ListMeta: obj.(*v2.SlackReceiverList).ListMeta}
	for _, item := range obj.(*v2.SlackReceiverList).Items {
		if label.Matches(labels.Set(item.Labels)) {
			list.Items = append(list.Items, item)
		}
	}
	return list, err
}

// Watch returns a watch.Interface that watches the requested slackReceivers.
func (c *FakeSlackReceivers) Watch(ctx context.Context, opts v1.ListOptions) (watch.Interface, error) {
	return c.Fake.
		InvokesWatch(testing.NewRootWatchAction(slackreceiversResource, opts))
}

// Create takes the representation of a slackReceiver and creates it.  Returns the server's representation of the slackReceiver, and an error, if there is any.
func (c *FakeSlackReceivers) Create(ctx context.Context, slackReceiver *v2.SlackReceiver, opts v1.CreateOptions) (result *v2.SlackReceiver, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootCreateAction(slackreceiversResource, slackReceiver), &v2.SlackReceiver{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackReceiver), err
}

// Update takes the representation of a slackReceiver and updates it. Returns the server's representation of the slackReceiver, and an error, if there is any.
func (c *FakeSlackReceivers) Update(ctx context.Context, slackReceiver *v2.SlackReceiver, opts v1.UpdateOptions) (result *v2.SlackReceiver, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateAction(slackreceiversResource, slackReceiver), &v2.SlackReceiver{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackReceiver), err
}

// UpdateStatus was generated because the type contains a Status member.
// Add a +genclient:noStatus comment above the type to avoid generating UpdateStatus().
func (c *FakeSlackReceivers) UpdateStatus(ctx context.Context, slackReceiver *v2.SlackReceiver, opts v1.UpdateOptions) (*v2.SlackReceiver, error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootUpdateSubresourceAction(slackreceiversResource, "status", slackReceiver), &v2.SlackReceiver{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackReceiver), err
}

// Delete takes name of the slackReceiver and deletes it. Returns an error if one occurs.
func (c *FakeSlackReceivers) Delete(ctx context.Context, name string, opts v1.DeleteOptions) error {
	_, err := c.Fake.
		Invokes(testing.NewRootDeleteAction(slackreceiversResource, name), &v2.SlackReceiver{})
	return err
}

// DeleteCollection deletes a collection of objects.
func (c *FakeSlackReceivers) DeleteCollection(ctx context.Context, opts v1.DeleteOptions, listOpts v1.ListOptions) error {
	action := testing.NewRootDeleteCollectionAction(slackreceiversResource, listOpts)

	_, err := c.Fake.Invokes(action, &v2.SlackReceiverList{})
	return err
}

// Patch applies the patch and returns the patched slackReceiver.
func (c *FakeSlackReceivers) Patch(ctx context.Context, name string, pt types.PatchType, data []byte, opts v1.PatchOptions, subresources ...string) (result *v2.SlackReceiver, err error) {
	obj, err := c.Fake.
		Invokes(testing.NewRootPatchSubresourceAction(slackreceiversResource, name, pt, data, subresources...), &v2.SlackReceiver{})
	if obj == nil {
		return nil, err
	}
	return obj.(*v2.SlackReceiver), err
}

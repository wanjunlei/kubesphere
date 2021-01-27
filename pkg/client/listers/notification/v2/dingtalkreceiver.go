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

// Code generated by lister-gen. DO NOT EDIT.

package v2

import (
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/client-go/tools/cache"
	v2 "kubesphere.io/kubesphere/pkg/apis/notification/v2"
)

// DingTalkReceiverLister helps list DingTalkReceivers.
type DingTalkReceiverLister interface {
	// List lists all DingTalkReceivers in the indexer.
	List(selector labels.Selector) (ret []*v2.DingTalkReceiver, err error)
	// Get retrieves the DingTalkReceiver from the index for a given name.
	Get(name string) (*v2.DingTalkReceiver, error)
	DingTalkReceiverListerExpansion
}

// dingTalkReceiverLister implements the DingTalkReceiverLister interface.
type dingTalkReceiverLister struct {
	indexer cache.Indexer
}

// NewDingTalkReceiverLister returns a new DingTalkReceiverLister.
func NewDingTalkReceiverLister(indexer cache.Indexer) DingTalkReceiverLister {
	return &dingTalkReceiverLister{indexer: indexer}
}

// List lists all DingTalkReceivers in the indexer.
func (s *dingTalkReceiverLister) List(selector labels.Selector) (ret []*v2.DingTalkReceiver, err error) {
	err = cache.ListAll(s.indexer, selector, func(m interface{}) {
		ret = append(ret, m.(*v2.DingTalkReceiver))
	})
	return ret, err
}

// Get retrieves the DingTalkReceiver from the index for a given name.
func (s *dingTalkReceiverLister) Get(name string) (*v2.DingTalkReceiver, error) {
	obj, exists, err := s.indexer.GetByKey(name)
	if err != nil {
		return nil, err
	}
	if !exists {
		return nil, errors.NewNotFound(v2.Resource("dingtalkreceiver"), name)
	}
	return obj.(*v2.DingTalkReceiver), nil
}

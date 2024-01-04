package main

import (
	"errors"
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/urfave/cli/v2"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/fake"
	clienttesting "k8s.io/client-go/testing"
)

func newUnstructured(apiVersion, kind, namespace, name string, annotations map[string]interface{}, labels map[string]interface{}) *unstructured.Unstructured {
	return &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": apiVersion,
			"kind":       kind,
			"metadata": map[string]interface{}{
				"namespace":   namespace,
				"name":        name,
				"labels":      labels,
				"annotations": annotations,
			},
		},
	}
}

func TestCreateJob(t *testing.T) {
	tcs := []struct {
		objects       []runtime.Object
		expects       map[string]int
		expectedError error
		handler       func(action clienttesting.Action) (handled bool, ret runtime.Object, err error)
	}{
		// old job exists.  It's supposed to delete and recreate one.
		{
			objects: []runtime.Object{
				newUnstructured(
					"batch/v1",
					"job",
					"neuvector",
					UPGRADER_JOB_NAME,
					map[string]interface{}{},
					map[string]interface{}{},
				),
			},
			expects: map[string]int{
				"create": 1,
				"delete": 1,
			},
			expectedError: nil,
			handler:       nil,
		},
		// old job exists, but the uid is consistent. It's supposed to skip creation.
		{
			objects: []runtime.Object{
				newUnstructured(
					"batch/v1",
					"job",
					"neuvector",
					UPGRADER_JOB_NAME,
					map[string]interface{}{
						"overrides": "uid",
					},
					map[string]interface{}{},
				),
			},
			expects:       map[string]int{},
			expectedError: nil,
			handler:       nil,
		},
		// nothing there.  It will just create a new job.
		{
			objects: []runtime.Object{},
			expects: map[string]int{
				"create": 1,
			},
			expectedError: nil,
			handler:       nil,
		},
		// Get job failed
		{
			objects: []runtime.Object{
				newUnstructured(
					"batch/v1",
					"job",
					"neuvector",
					UPGRADER_JOB_NAME,
					map[string]interface{}{},
					map[string]interface{}{},
				),
			},
			expects: map[string]int{
				"create": 1,
			},
			expectedError: nil,
			handler: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() == "get" {
					return true, nil, errors.New("error")
				}
				return true, nil, nil
			},
		},
		// Delete job failed
		{
			objects: []runtime.Object{
				newUnstructured(
					"batch/v1",
					"job",
					"neuvector",
					UPGRADER_JOB_NAME,
					map[string]interface{}{},
					map[string]interface{}{},
				),
			},
			expects: map[string]int{
				"create": 1,
			},
			expectedError: nil,
			handler: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() == "delete" {
					return true, nil, errors.New("error")
				}
				if action.GetVerb() == "get" {
					return true, newUnstructured(
						"batch/v1",
						"job",
						"neuvector",
						UPGRADER_JOB_NAME,
						map[string]interface{}{},
						map[string]interface{}{},
					), nil
				}
				return true, nil, nil
			},
		},
		// Delete job failed
		{
			objects: []runtime.Object{},
			expects: map[string]int{
				"create": 1,
			},
			expectedError: nil,
			handler: func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
				if action.GetVerb() == "create" {
					return true, nil, errors.New("error")
				}
				if action.GetVerb() == "get" {
					return true, newUnstructured(
						"batch/v1",
						"job",
						"neuvector",
						UPGRADER_JOB_NAME,
						map[string]interface{}{},
						map[string]interface{}{},
					), nil
				}
				return true, nil, nil
			},
		},
	}

	for _, tc := range tcs {

		events := map[string]int{}
		scheme := runtime.NewScheme()
		client := fake.NewSimpleDynamicClient(scheme,
			tc.objects...,
		)
		ctx := cli.NewContext(nil, nil, nil)
		defaulthandler := func(action clienttesting.Action) (handled bool, ret runtime.Object, err error) {
			events[action.GetVerb()]++
			return true, nil, nil
		}
		if tc.handler == nil {
			client.Fake.PrependReactor("create", "jobs", defaulthandler)
			//client.Fake.PrependReactor("get", "jobs", defaulthandler)
			client.Fake.PrependReactor("list", "jobs", defaulthandler)
			client.Fake.PrependReactor("patch", "jobs", defaulthandler)
			client.Fake.PrependReactor("update", "jobs", defaulthandler)
			client.Fake.PrependReactor("delete", "jobs", defaulthandler)
			err := CreatePostSyncJob(ctx, client, "neuvector", "uid", false)
			assert.Nil(t, err)
			assert.True(t, reflect.DeepEqual(tc.expects, events))
		} else {
			client.Fake.PrependReactor("create", "jobs", tc.handler)
			client.Fake.PrependReactor("get", "jobs", tc.handler)
			client.Fake.PrependReactor("list", "jobs", tc.handler)
			client.Fake.PrependReactor("patch", "jobs", tc.handler)
			client.Fake.PrependReactor("update", "jobs", tc.handler)
			client.Fake.PrependReactor("delete", "jobs", tc.handler)

			err := CreatePostSyncJob(ctx, client, "neuvector", "uid", false)
			assert.NotNil(t, err)
		}
	}
}

package orchestration

import (
	"os"
	"sync"
	"testing"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/container"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCustomServiceNameLabelGate verifies that the io.neuvector.service.name label is
// honored only when the feature is enabled, and that all drivers fall through to their
// normal service-name heuristics when it is disabled (the default).
func TestCustomServiceNameLabelGate(t *testing.T) {
	k8s := &kubernetes{noop: noop{platform: share.PlatformKubernetes}}
	baseDrv := &base{}
	ecsDrv := &ecs{}

	cases := []struct {
		name     string
		enabled  bool
		get      func() *Service
		expected string
	}{
		{
			name:    "k8s label honored when enabled",
			enabled: true,
			get: func() *Service {
				return k8s.GetServiceFromPodLabels("prod", "frontend-3823415956-853n5", "", map[string]string{
					container.NeuvectorSetServiceName: "MyApp",
					container.KubeKeyPodHash:          "3823415956",
				})
			},
			expected: "myapp",
		},
		{
			name:    "k8s label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return k8s.GetServiceFromPodLabels("prod", "frontend-3823415956-853n5", "", map[string]string{
					container.NeuvectorSetServiceName: "MyApp",
					container.KubeKeyPodHash:          "3823415956",
				})
			},
			expected: "frontend",
		},
		{
			name:    "docker label honored when enabled",
			enabled: true,
			get: func() *Service {
				return baseDrv.GetService(&container.ContainerMeta{
					Image:  "nginx:1.0",
					Labels: map[string]string{container.NeuvectorSetServiceName: "mydockersvc"},
				}, "")
			},
			expected: "mydockersvc",
		},
		{
			name:    "docker label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return baseDrv.GetService(&container.ContainerMeta{
					Image:  "nginx:1.0",
					Labels: map[string]string{container.NeuvectorSetServiceName: "mydockersvc"},
				}, "")
			},
			expected: "nginx",
		},
		{
			name:    "ecs label honored when enabled",
			enabled: true,
			get: func() *Service {
				return ecsDrv.GetService(&container.ContainerMeta{
					Labels: map[string]string{
						container.NeuvectorSetServiceName: "myecssvc",
						container.ECSCluster:              "cluster1",
						container.ECSTaskDefinition:       "task1",
						container.ECSContainerName:        "app",
					},
				}, "")
			},
			expected: "myecssvc",
		},
		{
			name:    "ecs label ignored when disabled",
			enabled: false,
			get: func() *Service {
				return ecsDrv.GetService(&container.ContainerMeta{
					Labels: map[string]string{
						container.NeuvectorSetServiceName: "myecssvc",
						container.ECSCluster:              "cluster1",
						container.ECSTaskDefinition:       "task1",
						container.ECSContainerName:        "app",
					},
				}, "")
			},
			expected: "cluster1.task1.app",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			old := enableCustomSvcName
			enableCustomSvcName = c.enabled
			defer func() { enableCustomSvcName = old }()

			svc := c.get()
			require.NotNil(t, svc)
			assert.Equal(t, c.expected, svc.Name)
		})
	}
}

// TestInitServiceNameGate verifies env-var parsing for the feature toggle.
func TestInitServiceNameGate(t *testing.T) {
	cases := []struct {
		name     string
		value    string
		set      bool
		expected bool
	}{
		{name: "unset stays disabled", set: false, expected: false},
		{name: "empty stays disabled", value: "", set: true, expected: false},
		{name: "1 enables", value: "1", set: true, expected: true},
		{name: "true enables", value: "true", set: true, expected: true},
		{name: "TRUE enables", value: "TRUE", set: true, expected: true},
		{name: "yes enables", value: "yes", set: true, expected: true},
		{name: "garbage stays disabled", value: "maybe", set: true, expected: false},
		{name: "0 stays disabled", value: "0", set: true, expected: false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv(share.ENV_EN_CUSTOM_SVC_NAME, "")
			if c.set {
				t.Setenv(share.ENV_EN_CUSTOM_SVC_NAME, c.value)
			} else {
				require.NoError(t, os.Unsetenv(share.ENV_EN_CUSTOM_SVC_NAME))
			}

			// reset the gate so we re-read the environment for each case
			enableCustomSvcName = false
			svcNameGateOnce = sync.Once{}
			initServiceNameGate()

			assert.Equal(t, c.expected, CustomServiceNameEnabled())
		})
	}
}

package rest

import (
	"testing"

	"github.com/neuvector/neuvector/controller/api"
	"github.com/stretchr/testify/assert"
)

// TestCompareWorkload verifies the compareWorkload function sorting logic
func TestCompareWorkload(t *testing.T) {
	tests := []struct {
		name     string
		p1       api.RESTScanReportAsset
		p2       api.RESTScanReportAsset
		expected int
	}{
		{
			name: "equal workloads",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: 0,
		},
		{
			name: "different domains - p1 less than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "prod",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: -1,
		},
		{
			name: "different domains - p1 greater than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "prod",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: 1,
		},
		{
			name: "same domain, different hostnames - p1 less than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host2",
				Name:     "workload1",
			},
			expected: -1,
		},
		{
			name: "same domain, different hostnames - p1 greater than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host2",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: 1,
		},
		{
			name: "same domain and hostname, different names - p1 less than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload2",
			},
			expected: -1,
		},
		{
			name: "same domain and hostname, different names - p1 greater than p2",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload2",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: 1,
		},
		{
			name: "empty domains",
			p1: api.RESTScanReportAsset{
				Domain:   "",
				HostName: "host1",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "",
				HostName: "host1",
				Name:     "workload1",
			},
			expected: 0,
		},
		{
			name: "empty hostnames with same domain",
			p1: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "",
				Name:     "workload1",
			},
			p2: api.RESTScanReportAsset{
				Domain:   "default",
				HostName: "",
				Name:     "workload1",
			},
			expected: 0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := compareWorkload(tc.p1, tc.p2)
			assert.Equal(t, tc.expected, result, "compareWorkload should return %d", tc.expected)
		})
	}
}

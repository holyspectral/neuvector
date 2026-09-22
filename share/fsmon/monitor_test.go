package fsmon

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/utils"
)

func TestGetBaseDirPrefix(t *testing.T) {
	assert.Equal(t, "/lib64", getBaseDirPrefix(share.CLUSFileMonitorFilter{Behavior: share.FileAccessBehaviorMonitor, Path: "/lib64", Regex: "ld-linux.*", Recursive: true}))
}

func TestMatchAppRule(t *testing.T) {
	const filterKey = "/etc/foo/"

	cases := []struct {
		name          string
		rules         map[string]utils.Set
		pInfo         *ProcInfo
		wantAllow     bool
		wantExcluded  bool
		wantInProfile bool
	}{
		{
			// no rules: default allow, not excluded
			name:      "no rules map",
			rules:     nil,
			pInfo:     &ProcInfo{Path: "/usr/bin/bar", Name: "bar"},
			wantAllow: true,
		},
		{
			// filter has no entry: deny (block-access), not excluded
			name:  "no entry for filter",
			rules: map[string]utils.Set{"/other/": utils.NewSet("/usr/bin/bar")},
			pInfo: &ProcInfo{Path: "/usr/bin/bar", Name: "bar"},
		},
		{
			name:  "entry present but empty set",
			rules: map[string]utils.Set{filterKey: utils.NewSet()},
			pInfo: &ProcInfo{Path: "/usr/bin/bar", Name: "bar"},
		},
		{
			name:          "match by full path",
			rules:         map[string]utils.Set{filterKey: utils.NewSet("/usr/bin/bar")},
			pInfo:         &ProcInfo{Path: "/usr/bin/bar", Name: "bar"},
			wantAllow:     true,
			wantExcluded:  true,
			wantInProfile: true,
		},
		{
			// basename matches but full path and Name do not, isolating the basename branch
			name:          "match by basename",
			rules:         map[string]utils.Set{filterKey: utils.NewSet("bar")},
			pInfo:         &ProcInfo{Path: "/usr/bin/bar", Name: "somethingelse"},
			wantAllow:     true,
			wantExcluded:  true,
			wantInProfile: true,
		},
		{
			// only Name matches: full path and basename ("python3.9") both differ from "python"
			name:          "match by name",
			rules:         map[string]utils.Set{filterKey: utils.NewSet("python")},
			pInfo:         &ProcInfo{Path: "/usr/bin/python3.9", Name: "python"},
			wantAllow:     true,
			wantExcluded:  true,
			wantInProfile: true,
		},
		{
			// entry present, no match: deny (block-access), not excluded
			name:  "present but no match",
			rules: map[string]utils.Set{filterKey: utils.NewSet("/usr/bin/other")},
			pInfo: &ProcInfo{Path: "/usr/bin/bar", Name: "bar"},
		},
		{
			// unknown process: default allow, not excluded
			name:      "empty process path",
			rules:     map[string]utils.Set{filterKey: utils.NewSet("/usr/bin/bar")},
			pInfo:     &ProcInfo{Path: "", Name: "bar"},
			wantAllow: true,
		},
		{
			name:      "nil process info",
			rules:     map[string]utils.Set{filterKey: utils.NewSet("/usr/bin/bar")},
			pInfo:     nil,
			wantAllow: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fn := &FaNotify{}
			r := &rootFd{rules: c.rules}
			ifile := &IFile{filter: &filterRegex{path: filterKey}}

			allow, excluded := fn.matchAppRule(r, ifile, c.pInfo, "/etc/foo/bar")
			assert.Equal(t, c.wantAllow, allow)
			assert.Equal(t, c.wantExcluded, excluded)
			if c.pInfo != nil {
				assert.Equal(t, c.wantInProfile, c.pInfo.InProfile)
			}
		})
	}
}

package types

import "time"

type ProcInternal struct {
	Pname        string
	Ppath        string
	Name         string
	Path         string
	Cmds         []string
	User         string
	Pid          int
	Ppid         int
	Sid          int
	Pgid         int
	Ruid         int
	Euid         int
	Retry        int
	InspectTimes uint
	StartTime    time.Time
	LastScanTime time.Time
	ScanTimes    uint
	Reported     uint
	Action       string
	RiskyChild   bool
	RiskType     string
	ExecScanDone bool // scan mode only
}

package bpfprocess

import (
	"errors"
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"

	log "github.com/sirupsen/logrus"
)

const (
	KPROBE_LINK                 = "kprobelink"
	LSM_FILEOPEN_LINK           = "lsmfileopenlink"
	LSM_BPRM_CRED_FOR_EXEC_LINK = "lsmbprmexeclink"
)

type BPFProcessControl struct {
	bpfObjects
	links map[string]link.Link
}

type ProcessEvent struct {
	Pid       uint32
	Tgid      uint32
	Uid       uint32
	Euid      uint32
	Gid       uint32
	Egid      uint32
	Ppid      uint32
	Ptgid     uint32
	Puid      uint32
	Peuid     uint32
	Pgid      uint32
	Pegid     uint32
	CurrIndex uint32
	CommIndex uint32
	ExecIndex uint32
	Buffer    [1024]uint8
}

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -target amd64 -type process_event -type string_lpm_trie bpf bpf/lsm.c bpf/kprobe.c -- -I./bpf/headers

func NewBPFProcessControl() *BPFProcessControl {
	return &BPFProcessControl{
		links: map[string]link.Link{},
	}
}

// Create a postfix lpm trie for filtering filename
func createPostfixLpmTrie(str string) *bpfStringLpmTrie {
	// Initialize inner map
	trie := bpfStringLpmTrie{
		Prefixlen: uint32(len(str) * 8),
	}

	// Reverse copy
	for i := 0; i < len(str); i++ {
		trie.Data[i] = str[len(str)-i-1]
	}

	return &trie
}

// Create a postfix lpm trie for filtering filename
func createPrefixLpmTrie(str string) *bpfStringLpmTrie {
	// Initialize inner map
	trie := bpfStringLpmTrie{
		Prefixlen: uint32(len(str) * 8),
	}

	copy(trie.Data[:], str)

	return &trie
}

// TODO: Convenient function.  Should not use this in production.
func (bpc *BPFProcessControl) GetEventRingBuffer() *ebpf.Map {
	return bpc.bpfObjects.RingbufEvents
}

func (bpc *BPFProcessControl) UpdatePolicy(containerID string, policy map[string]int) error {

	// Initialize map
	// Create per-container policy map
	// TODO: This needs to be modify according to ebpf map.
	m, err := ebpf.NewMapWithOptions(&ebpf.MapSpec{
		Name:       "inner",
		Type:       ebpf.LPMTrie,
		KeySize:    260,
		ValueSize:  2,
		MaxEntries: 1,
		Flags:      unix.BPF_F_NO_PREALLOC,
		//Pinning:    ebpf.PinByName,
	}, ebpf.MapOptions{
		PinPath: "/sys/fs/bpf/",
	})

	if err != nil {
		return fmt.Errorf("failed to create inner map: %w", err)
	}

	for path, verdict := range policy {
		trie := createPrefixLpmTrie(path)

		value := uint16(verdict)
		if err := m.Put(trie, &value); err != nil {
			return fmt.Errorf("failed to update inner map: %w", err)
		}
	}

	// TODO: shall we delete the existing map?

	fd := uint32(m.FD())
	if err := bpc.bpfObjects.FilenameMaps.Put(containerID, fd); err != nil {
		return fmt.Errorf("failed to update policy's inner map: %w", err)
	}
	return nil
}

/*
func (bpc *BPFProcessControl) InstallLSMHooks() error {
	lsm, err := link.AttachLSM(link.LSMOptions{
		Program: bpc.bpfObjects.LsmFileOpen,
	})
	if err != nil {
		return fmt.Errorf("failed to install lsm hooks on file_open: %w", err)
	}

	lsmcred, err := link.AttachLSM(link.LSMOptions{
		Program: bpc.bpfObjects.LsmBprmCredsForExec,
	})
	if err != nil {
		return fmt.Errorf("failed to attach lsm hooks on bprm_creds_for_exec: %w", err)
	}

	bpc.links[LSM_FILEOPEN_LINK] = lsm
	bpc.links[LSM_BPRM_CRED_FOR_EXEC_LINK] = lsmcred

	return nil
}
*/

func (bpc *BPFProcessControl) InstallKprobes() (link.Link, error) {

	/*
		kp, err := link.Kprobe("sys_execve", bpc.bpfObjects.KprobeExecve, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to install lsm hooks on file_open: %w", err)
		}
	*/

	/* kprobe enforcement
	kp, err := link.Kprobe("exec_binprm", bpc.bpfObjects.KprobeExecBinprm, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to install lsm hooks on file_open: %w", err)
	}
	*/

	kp, err := link.Kprobe("proc_fork_connector", bpc.bpfObjects.KprobeProcForkConnector, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to install hooks on proc_fork_connector: %w", err)
	}

	return kp, nil
}

func (bpc *BPFProcessControl) LoadObjects() error {
	// Load pre-compiled programs and maps
	if err := loadBpfObjects(&bpc.bpfObjects, nil); err != nil {
		var verr *ebpf.VerifierError
		if errors.As(err, &verr) {
			return fmt.Errorf("failed to load bpf objects: %+v", verr)
		}
		return fmt.Errorf("failed to load bpf objects: %w", err)
	}

	bpc.bpfObjects.ProgramsMap.Update(uint32(0), uint32(bpc.bpfObjects.CreateEvent.FD()), ebpf.UpdateAny)
	return nil
}

func (bpc *BPFProcessControl) Cleanup() error {
	bpc.bpfObjects.Close()
	for _, link := range bpc.links {
		link.Close()
	}
	log.Info("cleanup")
	return nil
}

/*
func (bpc *BPFProcessControl) StartLSMHooks() error {
	err := bpc.InstallLSMHooks()
	if err != nil {
		return fmt.Errorf("failed to install LSM hooks: %w", err)
	}
	return nil
}
*/

func (bpc *BPFProcessControl) StartKProbe() error {
	kp, err := bpc.InstallKprobes()
	if err != nil {
		return fmt.Errorf("failed to attach to kprobe: %w", err)
	}
	bpc.links[KPROBE_LINK] = kp

	return nil
}

func (bpc *BPFProcessControl) Test() {
	log.Println(bpc.bpfObjects.bpfPrograms)
}

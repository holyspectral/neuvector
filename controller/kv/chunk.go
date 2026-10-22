package kv

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

// Scan reports can exceed Consul's per-value limit (cluster.KVValueSizeMax,
// 512 KB), and a Consul transaction cannot hold a multi-chunk report (its body is
// also capped at ~512 KB / 64 ops). To store large reports atomically, a report
// is addressed indirectly:
//
//   - Reports that fit in one value keep the legacy single-value layout: the raw
//     gzip blob is stored at the base data key D. (Also rollback-friendly.)
//   - Larger reports are split into chunks under D/<gen>/<i>, and a small manifest
//     ({"g":"<gen>","n":<count>}) is written at D. The single Put of the manifest
//     is the atomic commit point: a reader follows the committed generation and
//     never observes a partial or stale chunk set.
//
// On read, the base key's first bytes discriminate the layout: gzip magic
// (0x1f 0x8b) means legacy/single-value (or the pre-redesign interim D/<i>
// layout), anything else is parsed as a manifest.

// Indirection points for the low-level KV primitives, overridden in unit tests
// (the share/cluster driver has no in-memory test implementation).
var (
	kvPutBinary    = cluster.PutBinary
	kvPut          = cluster.Put
	kvGet          = cluster.Get
	kvGetStoreKeys = cluster.GetStoreKeys
	kvDelete       = cluster.Delete
	kvDeleteTree   = cluster.DeleteTree
)

// reportManifest is the small value stored at the base data key when a report is
// chunked. Its leading '{' distinguishes it from a gzip blob (0x1f 0x8b).
type reportManifest struct {
	Gen    string `json:"g"`
	Chunks int    `json:"n"`
}

func isGzip(b []byte) bool {
	return len(b) >= 2 && b[0] == 0x1f && b[1] == 0x8b
}

// putReport stores the already-gzipped report blob at key, atomically. Small
// reports are written as a single value; large reports are chunked under a fresh
// generation and committed with a manifest Put. Stale keys from a previous
// report (old generations or interim tails) are garbage-collected after commit.
func putReport(key string, gz []byte) error {
	// Single-value fast path (also keeps old controllers able to read it).
	if len(gz) < cluster.KVValueSizeMax {
		if err := kvPutBinary(key, gz); err != nil {
			return err
		}
		// GC is best-effort: the report is already committed, so a cleanup error
		// must not fail the write (which would skip the summary update).
		if err := gcReportChildren(key, ""); err != nil {
			log.WithError(err).WithField("key", key).Warn("best-effort GC of stale report keys failed")
		}
		return nil
	}

	gen, err := utils.GetRandomID(8, "")
	if err != nil {
		return fmt.Errorf("failed to generate report generation id: %w", err)
	}
	genPrefix := fmt.Sprintf("%s/%s", key, gen)

	n, err := writeReportChunks(genPrefix, gz)
	if err != nil {
		return err
	}

	man, err := json.Marshal(reportManifest{Gen: gen, Chunks: n})
	if err != nil {
		return err
	}
	// Atomic commit: flip the base key to the new manifest in a single Put.
	if err := kvPut(key, man); err != nil {
		return err
	}
	// GC is best-effort: the report is already committed, so a cleanup error must
	// not fail the write (which would skip the summary update).
	if err := gcReportChildren(key, genPrefix); err != nil {
		log.WithError(err).WithField("key", key).Warn("best-effort GC of stale report keys failed")
	}
	return nil
}

// writeReportChunks splits gz into KV-sized pieces written at prefix/0..n-1 and
// returns the number of chunks written.
func writeReportChunks(prefix string, gz []byte) (int, error) {
	buffer := bytes.NewBuffer(gz)
	chunk := make([]byte, cluster.KVValueSizeMax-1)
	n := 0
	for {
		c, err := buffer.Read(chunk)
		if c > 0 {
			if werr := kvPutBinary(fmt.Sprintf("%s/%d", prefix, n), chunk[:c]); werr != nil {
				return n, werr
			}
			n++
		}
		if err == io.EOF || c == 0 {
			break
		}
		if err != nil {
			return n, err
		}
	}
	return n, nil
}

// getReport returns the still-gzipped report blob stored at key, or nil bytes if
// absent. It handles the single-value/legacy layout and the manifest layout.
func getReport(key string) ([]byte, error) {
	base, err := kvGet(key)
	if err != nil {
		return nil, err
	}
	if len(base) == 0 {
		return nil, nil
	}

	if isGzip(base) {
		// Legacy single-value, or the pre-redesign interim base+D/<i> layout.
		return getKVChunks(key)
	}

	var man reportManifest
	if err := json.Unmarshal(base, &man); err != nil || man.Chunks <= 0 {
		// Not a recognizable manifest; hand the raw bytes back so the caller's
		// gunzip fails and the report is treated as absent rather than corrupt.
		return base, nil
	}
	return readReportChunks(fmt.Sprintf("%s/%s", key, man.Gen), man.Chunks)
}

// readReportChunks reads prefix/0..count-1 and returns the concatenated bytes.
func readReportChunks(prefix string, count int) ([]byte, error) {
	var combined bytes.Buffer
	for i := 0; i < count; i++ {
		value, err := kvGet(fmt.Sprintf("%s/%d", prefix, i))
		if err != nil {
			return nil, err
		}
		combined.Write(value)
	}
	return combined.Bytes(), nil
}

// deleteReport removes the base key and every child (manifest, all generations,
// and any legacy tail keys) for a report.
func deleteReport(key string) error {
	return kvDeleteTree(key)
}

// gcReportChildren deletes keys under the report's base key, keeping the base key
// itself and (when keepPrefix is non-empty) the committed generation's chunks.
func gcReportChildren(key, keepPrefix string) error {
	children, err := kvGetStoreKeys(key)
	if err != nil {
		return err
	}
	for _, k := range children {
		if k == key {
			continue
		}
		if keepPrefix != "" && (k == keepPrefix || strings.HasPrefix(k, keepPrefix+"/")) {
			continue
		}
		if derr := kvDelete(k); derr != nil {
			return derr
		}
	}
	return nil
}

// getKVChunks is the legacy reader: it concatenates the base key with key/1,
// key/2, ... until a chunk is missing, returning the combined (still-gzipped)
// bytes. It reads pre-redesign reports (true single-value and the interim
// base-chunk-0 + key/<i> layout).
func getKVChunks(key string) ([]byte, error) {
	var combined bytes.Buffer
	for index := 0; ; index++ {
		expandKey := key
		if index > 0 {
			expandKey = fmt.Sprintf("%s/%d", key, index)
		}
		value, err := kvGet(expandKey)
		if err != nil {
			if index == 0 {
				return nil, err
			}
			break
		}
		combined.Write(value)
	}
	return combined.Bytes(), nil
}

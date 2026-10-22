package kv

import (
	"bytes"
	"crypto/rand"
	"encoding/gob"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/neuvector/neuvector/share"
	"github.com/neuvector/neuvector/share/cluster"
	"github.com/neuvector/neuvector/share/utils"
)

// withMemKV installs an in-memory KV backing the report helpers and restores the
// real cluster primitives (and KVValueSizeMax) when the test ends. It returns the
// backing map so tests can inspect stored keys.
func withMemKV(t *testing.T, sizeMax int) map[string][]byte {
	t.Helper()
	store := make(map[string][]byte)

	origPutBinary, origPut, origGet := kvPutBinary, kvPut, kvGet
	origGetStoreKeys, origDelete, origDeleteTree := kvGetStoreKeys, kvDelete, kvDeleteTree
	origMax := cluster.KVValueSizeMax
	t.Cleanup(func() {
		kvPutBinary, kvPut, kvGet = origPutBinary, origPut, origGet
		kvGetStoreKeys, kvDelete, kvDeleteTree = origGetStoreKeys, origDelete, origDeleteTree
		cluster.KVValueSizeMax = origMax
	})

	cluster.KVValueSizeMax = sizeMax
	putFn := func(key string, value []byte) error {
		if len(value) >= cluster.KVValueSizeMax {
			return fmt.Errorf("size too big: %d >= %d", len(value), cluster.KVValueSizeMax)
		}
		cp := make([]byte, len(value))
		copy(cp, value)
		store[key] = cp
		return nil
	}
	kvPutBinary = putFn
	kvPut = putFn
	kvGet = func(key string) ([]byte, error) {
		if v, ok := store[key]; ok {
			return v, nil
		}
		return nil, cluster.ErrKeyNotFound
	}
	kvGetStoreKeys = func(prefix string) ([]string, error) {
		keys := []string{}
		for k := range store {
			if k == prefix || strings.HasPrefix(k, prefix+"/") {
				keys = append(keys, k)
			}
		}
		return keys, nil
	}
	kvDelete = func(key string) error {
		delete(store, key)
		return nil
	}
	kvDeleteTree = func(prefix string) error {
		for k := range store {
			if k == prefix || strings.HasPrefix(k, prefix+"/") {
				delete(store, k)
			}
		}
		return nil
	}
	return store
}

func storeKeys(store map[string][]byte) []string {
	keys := make([]string, 0, len(store))
	for k := range store {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// gzBlob returns the gzip of n random (incompressible) bytes, so its size is
// predictable (>= n) regardless of compression — real reports are gzip and the
// helper branches on the gzip magic header.
func gzBlob(t *testing.T, n int) []byte {
	t.Helper()
	raw := make([]byte, n)
	_, err := rand.Read(raw)
	require.NoError(t, err)
	gz := utils.GzipBytes(raw)
	require.True(t, isGzip(gz), "GzipBytes output must start with the gzip magic")
	return gz
}

const testDataKey = "scan/data/image/reg/img"

func TestPutGetReport(t *testing.T) {
	cases := []struct {
		name        string
		sizeMax     int
		blobLen     int
		wantChunked bool
	}{
		{name: "single value", sizeMax: 1 << 20, blobLen: 100, wantChunked: false},
		{name: "chunked manifest", sizeMax: 64, blobLen: 2000, wantChunked: true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			store := withMemKV(t, c.sizeMax)
			blob := gzBlob(t, c.blobLen)
			require.NoError(t, putReport(testDataKey, blob))

			base := store[testDataKey]
			require.NotNil(t, base, "base key must exist")
			if c.wantChunked {
				assert.False(t, isGzip(base), "base should be a manifest, not gzip")
				assert.Greater(t, len(store), 1, "expected manifest + chunk keys")
			} else {
				assert.True(t, isGzip(base), "base should hold the raw gzip blob")
				assert.Equal(t, []string{testDataKey}, storeKeys(store), "single value: only the base key")
			}

			got, err := getReport(testDataKey)
			require.NoError(t, err)
			assert.Equal(t, blob, got, "round-trip blob")
		})
	}
}

func TestPutReportGrowAndShrink(t *testing.T) {
	store := withMemKV(t, 64)
	small := gzBlob(t, 5)    // gzips below 64 -> single value
	large := gzBlob(t, 2000) // exceeds 64 -> chunked

	// small -> large: base flips to a manifest.
	require.NoError(t, putReport(testDataKey, small))
	require.NoError(t, putReport(testDataKey, large))
	got, err := getReport(testDataKey)
	require.NoError(t, err)
	assert.Equal(t, large, got)
	assert.False(t, isGzip(store[testDataKey]))

	// large -> small: base flips back to a single value, generation chunks GC'd.
	require.NoError(t, putReport(testDataKey, small))
	assert.Equal(t, []string{testDataKey}, storeKeys(store), "stale generation chunks must be removed")
	got, err = getReport(testDataKey)
	require.NoError(t, err)
	assert.Equal(t, small, got)
}

// TestPutReportLargeToLarge verifies a second chunked generation GCs the first
// generation's chunks (the common steady-state re-scan path).
func TestPutReportLargeToLarge(t *testing.T) {
	store := withMemKV(t, 64)
	require.NoError(t, putReport(testDataKey, gzBlob(t, 2000)))
	large2 := gzBlob(t, 2500)
	require.NoError(t, putReport(testDataKey, large2))

	got, err := getReport(testDataKey)
	require.NoError(t, err)
	assert.Equal(t, large2, got)

	// Every non-base key must belong to the currently committed generation.
	var man reportManifest
	require.NoError(t, json.Unmarshal(store[testDataKey], &man))
	genPrefix := fmt.Sprintf("%s/%s/", testDataKey, man.Gen)
	for _, k := range storeKeys(store) {
		if k == testDataKey {
			continue
		}
		assert.Truef(t, strings.HasPrefix(k, genPrefix), "stale key from an old generation not GC'd: %s", k)
	}
}

// TestPutReportGCErrorDoesNotFailCommit verifies that a best-effort GC failure
// after the atomic commit does not fail the write and does not corrupt the report.
func TestPutReportGCErrorDoesNotFailCommit(t *testing.T) {
	withMemKV(t, 64)
	// Commit a first generation so there is stale content for the next write to GC.
	require.NoError(t, putReport(testDataKey, gzBlob(t, 2000)))

	// Make cleanup deletes fail; the next write still commits a new generation.
	kvDelete = func(string) error { return fmt.Errorf("transient kv error") }

	large2 := gzBlob(t, 2500)
	require.NoError(t, putReport(testDataKey, large2), "GC error must not fail an already-committed write")

	got, err := getReport(testDataKey)
	require.NoError(t, err)
	assert.Equal(t, large2, got)
}

// TestGetReportAtomicCommit proves that if new-generation chunks exist but the
// manifest has not been flipped, readers still get the previously committed report
// (never a partial/corrupt one).
func TestGetReportAtomicCommit(t *testing.T) {
	withMemKV(t, 64)
	reportA := gzBlob(t, 2000)
	require.NoError(t, putReport(testDataKey, reportA))

	// Simulate an in-progress write of a new generation whose manifest has NOT been
	// committed (base key untouched).
	reportB := gzBlob(t, 2000)
	_, err := writeReportChunks(fmt.Sprintf("%s/%s", testDataKey, "pendinggen"), reportB)
	require.NoError(t, err)

	got, err := getReport(testDataKey)
	require.NoError(t, err)
	assert.Equal(t, reportA, got, "reader must see the committed generation, not the in-progress one")
}

func TestDeleteReport(t *testing.T) {
	store := withMemKV(t, 64)
	require.NoError(t, putReport(testDataKey, gzBlob(t, 2000)))
	require.NotEmpty(t, storeKeys(store))

	require.NoError(t, deleteReport(testDataKey))
	assert.Empty(t, storeKeys(store), "delete must remove base + all chunks")
	got, err := getReport(testDataKey)
	require.Error(t, err)
	assert.Nil(t, got)
}

func TestGetReportLegacyLayouts(t *testing.T) {
	t.Run("single value", func(t *testing.T) {
		store := withMemKV(t, 1<<20)
		blob := gzBlob(t, 200)
		store[testDataKey] = blob // written by old code as one gzip value
		got, err := getReport(testDataKey)
		require.NoError(t, err)
		assert.Equal(t, blob, got)
	})

	t.Run("interim base plus tail chunks", func(t *testing.T) {
		store := withMemKV(t, 1<<20)
		full := gzBlob(t, 350)
		half := len(full) / 2
		store[testDataKey] = full[:half]                      // interim chunk 0 (starts with gzip magic)
		store[fmt.Sprintf("%s/1", testDataKey)] = full[half:] // interim chunk 1
		got, err := getReport(testDataKey)
		require.NoError(t, err)
		assert.Equal(t, full, got)
	})
}

// TestScanReportRoundTrip exercises the real data path: gob-encode + gzip a report,
// store it (forced to chunk), read it back, gunzip + gob-decode, and compare.
func TestScanReportRoundTrip(t *testing.T) {
	withMemKV(t, 4096)

	report := &share.CLUSScanReport{Registry: "reg", Repository: "repo", Tag: "tag"}
	for i := 0; i < 5000; i++ {
		report.Vuls = append(report.Vuls, &share.ScanVulnerability{
			Name:        fmt.Sprintf("CVE-2026-%05d", i),
			Severity:    "High",
			PackageName: fmt.Sprintf("pkg-%d", i),
			Description: "a reasonably long vulnerability description to inflate size",
		})
	}

	var buf bytes.Buffer
	require.NoError(t, gob.NewEncoder(&buf).Encode(report))
	gz := utils.GzipBytes(buf.Bytes())
	require.Greater(t, len(gz), cluster.KVValueSizeMax, "report must exceed the KV limit to exercise chunking")

	require.NoError(t, putReport(testDataKey, gz))

	combined, err := getReport(testDataKey)
	require.NoError(t, err)
	uzb := utils.GunzipBytes(combined)
	require.NotNil(t, uzb)
	var got share.CLUSScanReport
	require.NoError(t, gob.NewDecoder(bytes.NewBuffer(uzb)).Decode(&got))

	require.Len(t, got.Vuls, len(report.Vuls))
	assert.Equal(t, report.Vuls[0].Name, got.Vuls[0].Name)
	assert.Equal(t, report.Vuls[len(report.Vuls)-1].Name, got.Vuls[len(got.Vuls)-1].Name)
}

package store

import (
	"path/filepath"
	"testing"
	"time"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "s.db"), true, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func TestPurgeRejectionsOlderThan(t *testing.T) {
	st := openTest(t)
	st.LogRejection(Rejection{At: time.Now().Add(-100 * 24 * time.Hour), Stage: "auth", Code: 535, Reason: "old"})
	st.LogRejection(Rejection{At: time.Now(), Stage: "auth", Code: 535, Reason: "recent"})

	n, err := st.PurgeRejectionsOlderThan(time.Now().Add(-90 * 24 * time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("purged %d, want 1", n)
	}
	rows, _ := st.RecentRejections(10)
	if len(rows) != 1 || rows[0].Reason != "recent" {
		t.Errorf("after purge want [recent], got %+v", rows)
	}
}

func TestDeleteRejections(t *testing.T) {
	st := openTest(t)
	st.LogRejection(Rejection{At: time.Now(), Stage: "auth", Reason: "a"})
	st.LogRejection(Rejection{At: time.Now(), Stage: "auth", Reason: "b"})
	rows, _ := st.RecentRejections(10)
	if len(rows) != 2 {
		t.Fatalf("want 2, got %d", len(rows))
	}
	if _, err := st.DeleteRejections([]int64{rows[0].ID}); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.RecentRejections(10); len(rows) != 1 {
		t.Errorf("after delete one: %d left", len(rows))
	}
	if _, err := st.DeleteAllRejections(); err != nil {
		t.Fatal(err)
	}
	if rows, _ = st.RecentRejections(10); len(rows) != 0 {
		t.Errorf("after delete all: %d left", len(rows))
	}
}

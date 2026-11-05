package engine

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// A-L7 regression (Batch 7): task records and log files used to grow
// without bound — every task permanently added a record and a log
// file. Retention is now capped on insert (DefaultMaxRetainedTasks
// = 200 in production); the oldest finished tasks are evicted with
// their log files, and running tasks are never evicted.

func newBatch7TaskManager(t *testing.T, cap int) *TaskManager {
	t.Helper()
	return &TaskManager{
		tasks:       make(map[string]*TaskRecord),
		node:        "test",
		logDir:      t.TempDir(),
		maxRetained: cap,
	}
}

func waitForAllTasksFinished(t *testing.T, m *TaskManager) {
	t.Helper()
	waitForTasksFinished(t, m, nil)
}

// waitForTasksFinished waits until every listed task (or every task
// when upids is nil) has left "running" status.
func waitForTasksFinished(t *testing.T, m *TaskManager, upids []string) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		allDone := true
		if upids == nil {
			for _, task := range m.ListTasks(0) {
				if task.Status == "running" {
					allDone = false
					break
				}
			}
		} else {
			for _, upid := range upids {
				task, err := m.GetTask(upid)
				if err != nil {
					t.Fatalf("task %s disappeared while waiting: %v", upid, err)
				}
				if task.Status == "running" {
					allDone = false
					break
				}
			}
		}
		if allDone {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("timed out waiting for test tasks to finish")
}

func logFileNames(t *testing.T, m *TaskManager) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(m.logDir)
	if err != nil {
		t.Fatalf("failed to list task log dir: %v", err)
	}
	names := make(map[string]bool, len(entries))
	for _, e := range entries {
		names[e.Name()] = true
	}
	return names
}

func TestBatch7TaskRetentionCapsRecordsAndLogs(t *testing.T) {
	m := newBatch7TaskManager(t, 5)

	// Insert 8 quick tasks, then wait for them all to finish.
	var upids []string
	for i := 0; i < 8; i++ {
		upids = append(upids, m.StartTask("test", "target", "root@axonwall", func(log func(string, ...any)) error {
			return nil
		}))
	}
	waitForAllTasksFinished(t, m)

	// One more insert triggers the prune: 9 retained -> 5.
	m.StartTask("test", "target", "root@axonwall", func(log func(string, ...any)) error {
		return nil
	})
	waitForAllTasksFinished(t, m)

	tasks := m.ListTasks(0)
	if len(tasks) > 5 {
		t.Fatalf("retained tasks must be capped at 5, got %d", len(tasks))
	}
	if len(tasks) != 5 {
		t.Fatalf("expected exactly 5 retained tasks after pruning, got %d", len(tasks))
	}

	// The 4 oldest tasks are gone, with their log files; the 5
	// newest remain with theirs.
	names := logFileNames(t, m)
	if len(names) != 5 {
		t.Fatalf("expected 5 log files on disk, got %d", len(names))
	}
	for i, upid := range upids {
		logName := strings.ReplaceAll(upid, ":", "_") + ".log"
		_, stillOnDisk := names[logName]
		if i < 4 && stillOnDisk {
			t.Errorf("evicted task %d still has a log file on disk: %s", i, logName)
		}
		if i >= 4 && !stillOnDisk {
			t.Errorf("retained task %d lost its log file: %s", i, logName)
		}
		if _, err := m.GetTask(upid); i < 4 && err == nil {
			t.Errorf("evicted task %d is still retrievable", i)
		}
		if _, err := m.GetTask(upid); i >= 4 && err != nil {
			t.Errorf("retained task %d is no longer retrievable: %v", i, err)
		}
	}
}

func TestBatch7TaskRetentionNeverEvictsRunningTasks(t *testing.T) {
	m := newBatch7TaskManager(t, 5)

	// A task that stays running until the test releases it.
	release := make(chan struct{})
	blocking := m.StartTask("test", "blocking", "root@axonwall", func(log func(string, ...any)) error {
		<-release
		return nil
	})
	// Give the goroutine a moment to start so the record is
	// "running" before the flood of inserts.
	time.Sleep(50 * time.Millisecond)

	for i := 0; i < 8; i++ {
		m.StartTask("test", "target", "root@axonwall", func(log func(string, ...any)) error {
			return nil
		})
	}
	// Wait for the quick tasks only: the blocking task is still
	// running by design, and must survive the prune that the
	// inserts above triggered.
	quick := make([]string, 0, 8)
	for _, task := range m.ListTasks(0) {
		if task.UPID != blocking {
			quick = append(quick, task.UPID)
		}
	}
	waitForTasksFinished(t, m, quick)

	// The blocking task must still be present even though the
	// retained count exceeded the cap while it was running.
	if _, err := m.GetTask(blocking); err != nil {
		t.Fatalf("running task was evicted by retention pruning: %v", err)
	}
	blockingLog := filepath.Join(m.logDir, strings.ReplaceAll(blocking, ":", "_")+".log")
	if _, err := os.Stat(blockingLog); err != nil {
		t.Fatalf("running task lost its log file: %v", err)
	}

	close(release)
	waitForAllTasksFinished(t, m)
}

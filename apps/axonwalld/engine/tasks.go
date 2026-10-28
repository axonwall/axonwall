package engine

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

type TaskRecord struct {
	UPID       string `json:"upid"`
	Node       string `json:"node"`
	PID        int    `json:"pid"`
	StartTime  int64  `json:"startTime"`
	EndTime    int64  `json:"endTime,omitempty"`
	Type       string `json:"type"`
	TargetID   string `json:"targetId"`
	User       string `json:"user"`
	Status     string `json:"status"` // "running", "stopped", "failed"
	ExitStatus string `json:"exitStatus"`
	LogFile    string `json:"logFile"`
}

type TaskManager struct {
	mu      sync.RWMutex
	tasks   map[string]*TaskRecord
	node    string
	logDir  string
	counter uint64
}

func NewTaskManager() *TaskManager {
	nodeName, err := os.Hostname()
	if err != nil || nodeName == "" {
		nodeName = "axonwall"
	}
	logDir := "/var/log/axonwall/tasks"
	if err := os.MkdirAll(logDir, 0755); err != nil {
		logDir = filepath.Join(os.TempDir(), "axonwall", "tasks")
		_ = os.MkdirAll(logDir, 0755)
	}

	return &TaskManager{
		tasks:  make(map[string]*TaskRecord),
		node:   nodeName,
		logDir: logDir,
	}
}

// GenerateUPID produces a Proxmox-compatible UPID: UPID:<node>:<pid>:<pstart>:<starttime>:<type>:<id>:<user>:
func (m *TaskManager) GenerateUPID(taskType, targetId, user string) string {
	now := time.Now().Unix()
	pid := os.Getpid()
	m.mu.Lock()
	m.counter++
	pstart := m.counter
	m.mu.Unlock()

	sanitizeUPIDToken := func(s string) string {
		s = strings.ReplaceAll(s, ":", "_")
		s = strings.ReplaceAll(s, "/", "_")
		s = strings.ReplaceAll(s, "\\", "_")
		s = strings.ReplaceAll(s, "..", "_")
		return s
	}
	cleanType := sanitizeUPIDToken(taskType)
	cleanId := sanitizeUPIDToken(targetId)
	cleanUser := sanitizeUPIDToken(user)
	if cleanUser == "" {
		cleanUser = "root@axonwall"
	}

	return fmt.Sprintf("UPID:%s:%08X:%08X:%08X:%s:%s:%s:",
		m.node, pid, pstart, now, cleanType, cleanId, cleanUser)
}

func (m *TaskManager) StartTask(taskType, targetId, user string, fn func(log func(format string, args ...any)) error) string {
	upid := m.GenerateUPID(taskType, targetId, user)
	safeUpidFile := strings.ReplaceAll(upid, ":", "_") + ".log"
	logPath := filepath.Join(m.logDir, safeUpidFile)

	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		fallbackDir := filepath.Join(os.TempDir(), "axonwall", "tasks")
		_ = os.MkdirAll(fallbackDir, 0755)
		logPath = filepath.Join(fallbackDir, safeUpidFile)
		logFile, _ = os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	}

	task := &TaskRecord{
		UPID:       upid,
		Node:       m.node,
		PID:        os.Getpid(),
		StartTime:  time.Now().Unix(),
		Type:       taskType,
		TargetID:   targetId,
		User:       user,
		Status:     "running",
		ExitStatus: "RUNNING",
		LogFile:    logPath,
	}

	m.mu.Lock()
	m.tasks[upid] = task
	m.mu.Unlock()

	if logFile != nil {
		_, _ = fmt.Fprintf(logFile, "TASK %s STARTED at %s by %s\n", upid, time.Now().Format(time.RFC3339), user)
		_ = logFile.Sync()
	}

	logger := func(format string, args ...any) {
		msg := fmt.Sprintf(format, args...)
		timestamped := fmt.Sprintf("[%s] %s\n", time.Now().Format("15:04:05"), strings.TrimRight(msg, "\n"))
		if logFile != nil {
			_, _ = logFile.WriteString(timestamped)
			_ = logFile.Sync()
		}
	}

	go func() {
		defer func() {
			if logFile != nil {
				_ = logFile.Close()
			}
		}()

		taskErr := fn(logger)

		m.mu.Lock()
		defer m.mu.Unlock()

		task.EndTime = time.Now().Unix()
		if taskErr != nil {
			task.Status = "failed"
			task.ExitStatus = taskErr.Error()
			logger("TASK FAILED: %v", taskErr)
		} else {
			task.Status = "stopped"
			task.ExitStatus = "OK"
			logger("TASK COMPLETED: OK")
		}
	}()

	return upid
}

func (m *TaskManager) GetTask(upid string) (*TaskRecord, error) {
	m.mu.RLock()
	defer m.mu.RUnlock()

	task, exists := m.tasks[upid]
	if !exists {
		return nil, fmt.Errorf("task not found: %s", upid)
	}
	return task, nil
}

func (m *TaskManager) ListTasks(limit int) []*TaskRecord {
	m.mu.RLock()
	defer m.mu.RUnlock()

	result := make([]*TaskRecord, 0, len(m.tasks))
	for _, t := range m.tasks {
		result = append(result, t)
	}

	// Sort descending by StartTime
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[i].StartTime < result[j].StartTime {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && len(result) > limit {
		return result[:limit]
	}
	return result
}

func (m *TaskManager) GetTaskLog(upid string, startLine int) ([]string, bool, error) {
	task, err := m.GetTask(upid)
	if err != nil {
		return nil, false, err
	}

	file, err := os.Open(task.LogFile)
	if err != nil {
		return nil, task.Status != "running", nil
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	currentLine := 0

	for scanner.Scan() {
		currentLine++
		if currentLine >= startLine {
			lines = append(lines, scanner.Text())
		}
	}

	return lines, task.Status != "running", nil
}

func (m *TaskManager) HandleStreamTaskLogSSE(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	upid := strings.TrimSpace(r.URL.Query().Get("upid"))
	if upid == "" {
		http.Error(w, "Missing upid query parameter", http.StatusBadRequest)
		return
	}

	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	ctx := r.Context()
	lineCursor := 1

	for {
		select {
		case <-ctx.Done():
			return
		default:
			lines, done, err := m.GetTaskLog(upid, lineCursor)
			if err != nil {
				_, _ = fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
				flusher.Flush()
				return
			}

			for _, l := range lines {
				_, _ = fmt.Fprintf(w, "data: %s\n\n", l)
				lineCursor++
			}
			flusher.Flush()

			if done {
				_, _ = fmt.Fprintf(w, "event: end\ndata: TASK_FINISHED\n\n")
				flusher.Flush()
				return
			}

			time.Sleep(500 * time.Millisecond)
		}
	}
}

func ParseStartLine(v string) int {
	if n, err := strconv.Atoi(v); err == nil && n > 0 {
		return n
	}
	return 1
}

package engine

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

type TerminalExecRequest struct {
	Command string `json:"command"`
	Cwd     string `json:"cwd,omitempty"`
	Timeout int    `json:"timeoutSeconds,omitempty"`
}

type TerminalExecResponse struct {
	Command   string `json:"command"`
	Output    string `json:"output"`
	ExitCode  int    `json:"exitCode"`
	LatencyMs int64  `json:"latencyMs"`
	Success   bool   `json:"success"`
}

type TerminalManager struct{}

func NewTerminalManager() *TerminalManager {
	return &TerminalManager{}
}

func (m *TerminalManager) Execute(ctx context.Context, req TerminalExecRequest) (*TerminalExecResponse, error) {
	cmdStr := strings.TrimSpace(req.Command)
	if cmdStr == "" {
		return nil, fmt.Errorf("empty command")
	}

	timeout := 15 * time.Second
	if req.Timeout > 0 && req.Timeout <= 60 {
		timeout = time.Duration(req.Timeout) * time.Second
	}

	execCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	start := time.Now()
	cmd := exec.CommandContext(execCtx, "/bin/bash", "-c", cmdStr)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
	if req.Cwd != "" {
		cmd.Dir = req.Cwd
	}

	out, err := cmd.CombinedOutput()
	latency := time.Since(start).Milliseconds()

	exitCode := 0
	if err != nil {
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = 1
		}
	}

	return &TerminalExecResponse{
		Command:   cmdStr,
		Output:    string(out),
		ExitCode:  exitCode,
		LatencyMs: latency,
		Success:   err == nil,
	}, nil
}

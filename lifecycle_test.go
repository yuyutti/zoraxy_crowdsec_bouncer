package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"
)

func TestPluginHelperProcess(t *testing.T) {
	if os.Getenv("BOUNCER_TEST_HELPER") != "1" {
		return
	}
	os.Args = []string{os.Args[0], "-configure", os.Getenv("BOUNCER_TEST_SPEC")}
	main()
	os.Exit(0)
}

// Real plugin startup with no configuration, confined to loopback and a temp
// directory. This is local process/HTTP evidence, not Zoraxy/CrowdSec E2E.
func TestOnboardingProcessAndShutdown(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	listener.Close()
	directory := t.TempDir()
	process := exec.Command(os.Args[0], "-test.run=^TestPluginHelperProcess$")
	process.Dir = directory
	process.Env = append(os.Environ(), "BOUNCER_TEST_HELPER=1", fmt.Sprintf("BOUNCER_TEST_SPEC={\"port\":%d}", port))
	if err := process.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			process.Process.Kill()
			process.Wait()
		}
	}()
	client := &http.Client{Timeout: time.Second}
	url := fmt.Sprintf("http://127.0.0.1:%d/api/config-status", port)
	deadline := time.Now().Add(10 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		response, err := client.Get(url)
		if err == nil {
			var status struct {
				State      string `json:"state"`
				Onboarding bool   `json:"onboarding"`
				Blocking   bool   `json:"blockingEnabled"`
			}
			json.NewDecoder(response.Body).Decode(&status)
			response.Body.Close()
			if status.State != "onboarding" || !status.Onboarding || status.Blocking {
				t.Fatalf("invalid onboarding: %+v", status)
			}
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("onboarding UI never became available")
	}
	if _, err := os.Stat(filepath.Join(directory, "config.yaml")); err != nil {
		t.Fatal("default config not created")
	}
	response, err := client.Get(fmt.Sprintf("http://127.0.0.1:%d/d_capture/", port))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != 403 || string(body) != "Forbidden" {
		t.Fatal("wire default response changed")
	}
	if runtime.GOOS != "windows" {
		if err := process.Process.Signal(syscall.SIGTERM); err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- process.Wait() }()
		select {
		case err := <-done:
			waited = true
			if err != nil {
				t.Fatal(err)
			}
		case <-time.After(5 * time.Second):
			t.Fatal("SIGTERM did not stop plugin")
		}
	} else {
		t.Log("SIGTERM process test is exercised by Linux CI; Windows process cleanup uses Kill")
	}
}

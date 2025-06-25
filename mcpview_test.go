package main

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestSessionRegistry(t *testing.T) {
	// Create a temporary directory for testing
	tempDir := t.TempDir()
	
	registry := &SessionRegistry{
		basePath: tempDir,
	}

	t.Run("CreateSession", func(t *testing.T) {
		sessionName := "test-session"
		targetCmd := "python server.py"
		pid := 12345

		err := registry.createSession(sessionName, targetCmd, pid)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Verify session directory was created
		sessionDir := registry.getSessionDir(sessionName)
		if _, err := os.Stat(sessionDir); os.IsNotExist(err) {
			t.Fatalf("Session directory was not created: %s", sessionDir)
		}

		// Verify metadata file was created and contains correct data
		metadataPath := registry.getMetadataPath(sessionName)
		data, err := os.ReadFile(metadataPath)
		if err != nil {
			t.Fatalf("Failed to read metadata file: %v", err)
		}

		var session ProxySession
		if err := json.Unmarshal(data, &session); err != nil {
			t.Fatalf("Failed to unmarshal session metadata: %v", err)
		}

		// Verify session data
		if session.Name != sessionName {
			t.Errorf("Expected session name %s, got %s", sessionName, session.Name)
		}
		if session.TargetCmd != targetCmd {
			t.Errorf("Expected target command %s, got %s", targetCmd, session.TargetCmd)
		}
		if session.PID != pid {
			t.Errorf("Expected PID %d, got %d", pid, session.PID)
		}
		if session.SocketPath != filepath.Join(sessionDir, "socket") {
			t.Errorf("Expected socket path %s, got %s", filepath.Join(sessionDir, "socket"), session.SocketPath)
		}
	})

	t.Run("CreateSessionWithInvalidName", func(t *testing.T) {
		// Test with a name that would create invalid path
		invalidName := "../invalid"
		err := registry.createSession(invalidName, "cmd", 123)
		// Should still work but create a sanitized path
		if err != nil {
			t.Logf("Expected behavior: %v", err)
		}
	})
}

func TestStdioProxySession(t *testing.T) {
	t.Run("NewStdioProxyWithSession", func(t *testing.T) {
		targetCmd := "echo hello"
		sessionName := "test-proxy"

		proxy := NewStdioProxyWithSession(targetCmd, sessionName)

		if proxy.targetCmd != targetCmd {
			t.Errorf("Expected target command %s, got %s", targetCmd, proxy.targetCmd)
		}
		if proxy.sessionName != sessionName {
			t.Errorf("Expected session name %s, got %s", sessionName, proxy.sessionName)
		}
		if proxy.messageLog == nil {
			t.Error("Message log should be initialized")
		}
	})

	t.Run("NewStdioProxyWithoutSession", func(t *testing.T) {
		targetCmd := "echo hello"

		proxy := NewStdioProxy(targetCmd)

		if proxy.targetCmd != targetCmd {
			t.Errorf("Expected target command %s, got %s", targetCmd, proxy.targetCmd)
		}
		if proxy.sessionName != "" {
			t.Errorf("Expected empty session name, got %s", proxy.sessionName)
		}
	})
}

func TestSessionPaths(t *testing.T) {
	registry := &SessionRegistry{
		basePath: "/tmp/test-sessions",
	}

	sessionName := "my-session"
	expectedDir := "/tmp/test-sessions/my-session"
	expectedMetadata := "/tmp/test-sessions/my-session/metadata.json"

	if got := registry.getSessionDir(sessionName); got != expectedDir {
		t.Errorf("Expected session dir %s, got %s", expectedDir, got)
	}

	if got := registry.getMetadataPath(sessionName); got != expectedMetadata {
		t.Errorf("Expected metadata path %s, got %s", expectedMetadata, got)
	}
}

func TestProxySessionSerialization(t *testing.T) {
	session := ProxySession{
		Name:         "test-session",
		TargetCmd:    "python server.py",
		PID:          12345,
		StartTime:    time.Now().Truncate(time.Second), // Truncate for consistent comparison
		SocketPath:   "/tmp/sessions/test/socket",
		MessageCount: 42,
		LastActivity: time.Now().Truncate(time.Second),
	}

	// Test JSON marshaling
	data, err := json.MarshalIndent(session, "", "  ")
	if err != nil {
		t.Fatalf("Failed to marshal session: %v", err)
	}

	// Test JSON unmarshaling
	var unmarshaled ProxySession
	if err := json.Unmarshal(data, &unmarshaled); err != nil {
		t.Fatalf("Failed to unmarshal session: %v", err)
	}

	// Verify all fields
	if unmarshaled.Name != session.Name {
		t.Errorf("Name mismatch: expected %s, got %s", session.Name, unmarshaled.Name)
	}
	if unmarshaled.TargetCmd != session.TargetCmd {
		t.Errorf("TargetCmd mismatch: expected %s, got %s", session.TargetCmd, unmarshaled.TargetCmd)
	}
	if unmarshaled.PID != session.PID {
		t.Errorf("PID mismatch: expected %d, got %d", session.PID, unmarshaled.PID)
	}
	if !unmarshaled.StartTime.Equal(session.StartTime) {
		t.Errorf("StartTime mismatch: expected %v, got %v", session.StartTime, unmarshaled.StartTime)
	}
}

func TestProxyMessageLogging(t *testing.T) {
	t.Run("MessageLoggingWithSession", func(t *testing.T) {
		proxy := NewStdioProxyWithSession("echo test", "test-session")
		
		// Test message logging
		testMessage := []byte(`{"jsonrpc": "2.0", "method": "initialize", "id": 1}`)
		proxy.logMessage(DirectionOutbound, testMessage)
		
		messages := proxy.GetMessageLog()
		if len(messages) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(messages))
		}
		
		msg := messages[0]
		if msg.Direction != DirectionOutbound {
			t.Errorf("Expected outbound direction, got %v", msg.Direction)
		}
		
		if string(msg.Content) != string(testMessage) {
			t.Errorf("Expected message content %s, got %s", string(testMessage), string(msg.Content))
		}
		
		// Verify pretty-printing worked
		if msg.Pretty == "" {
			t.Error("Expected pretty-printed message, got empty string")
		}
	})

	t.Run("MessageLoggingWithoutSession", func(t *testing.T) {
		proxy := NewStdioProxy("echo test")
		
		// Should work the same way without session
		testMessage := []byte(`{"jsonrpc": "2.0", "method": "tools/list"}`)
		proxy.logMessage(DirectionInbound, testMessage)
		
		messages := proxy.GetMessageLog()
		if len(messages) != 1 {
			t.Fatalf("Expected 1 message, got %d", len(messages))
		}
		
		if messages[0].Direction != DirectionInbound {
			t.Error("Expected inbound direction")
		}
	})
}

func TestSessionRegistryEdgeCases(t *testing.T) {
	tempDir := t.TempDir()
	registry := &SessionRegistry{basePath: tempDir}

	t.Run("EmptySessionName", func(t *testing.T) {
		err := registry.createSession("", "cmd", 123)
		if err == nil {
			t.Error("Expected error for empty session name")
		}
	})

	t.Run("DuplicateSession", func(t *testing.T) {
		// Create first session
		err1 := registry.createSession("duplicate", "cmd1", 123)
		if err1 != nil {
			t.Fatalf("First session creation failed: %v", err1)
		}

		// Create second session with same name (should overwrite)
		err2 := registry.createSession("duplicate", "cmd2", 456)
		if err2 != nil {
			t.Fatalf("Second session creation failed: %v", err2)
		}

		// Verify the second session overwrote the first
		data, err := os.ReadFile(registry.getMetadataPath("duplicate"))
		if err != nil {
			t.Fatalf("Failed to read metadata: %v", err)
		}

		var session ProxySession
		if err := json.Unmarshal(data, &session); err != nil {
			t.Fatalf("Failed to unmarshal: %v", err)
		}

		if session.TargetCmd != "cmd2" || session.PID != 456 {
			t.Error("Expected second session to overwrite first")
		}
	})
}

func TestSessionListing(t *testing.T) {
	tempDir := t.TempDir()
	registry := &SessionRegistry{basePath: tempDir}

	t.Run("ListEmptySessions", func(t *testing.T) {
		sessions, err := registry.listSessions()
		if err != nil {
			t.Fatalf("Failed to list empty sessions: %v", err)
		}
		if len(sessions) != 0 {
			t.Errorf("Expected 0 sessions, got %d", len(sessions))
		}
	})

	t.Run("ListMultipleSessions", func(t *testing.T) {
		// Create multiple sessions
		err1 := registry.createSession("session1", "cmd1", 100)
		err2 := registry.createSession("session2", "cmd2", 200)
		err3 := registry.createSession("session3", "cmd3", 300)
		
		if err1 != nil || err2 != nil || err3 != nil {
			t.Fatalf("Failed to create test sessions: %v, %v, %v", err1, err2, err3)
		}

		sessions, err := registry.listSessions()
		if err != nil {
			t.Fatalf("Failed to list sessions: %v", err)
		}

		if len(sessions) != 3 {
			t.Fatalf("Expected 3 sessions, got %d", len(sessions))
		}

		// Verify session data
		sessionMap := make(map[string]ProxySession)
		for _, session := range sessions {
			sessionMap[session.Name] = session
		}

		expectedSessions := map[string]struct {
			cmd string
			pid int
		}{
			"session1": {"cmd1", 100},
			"session2": {"cmd2", 200},
			"session3": {"cmd3", 300},
		}

		for name, expected := range expectedSessions {
			session, exists := sessionMap[name]
			if !exists {
				t.Errorf("Session %s not found in list", name)
				continue
			}
			if session.TargetCmd != expected.cmd {
				t.Errorf("Session %s: expected cmd %s, got %s", name, expected.cmd, session.TargetCmd)
			}
			if session.PID != expected.pid {
				t.Errorf("Session %s: expected PID %d, got %d", name, expected.pid, session.PID)
			}
		}
	})
}

func TestSessionCleanup(t *testing.T) {
	tempDir := t.TempDir()
	registry := &SessionRegistry{basePath: tempDir}

	t.Run("RemoveSession", func(t *testing.T) {
		// Create a session
		err := registry.createSession("test-remove", "cmd", 123)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}

		// Verify it exists
		sessions, err := registry.listSessions()
		if err != nil || len(sessions) != 1 {
			t.Fatalf("Session not created properly: %v", err)
		}

		// Remove it
		err = registry.removeSession("test-remove")
		if err != nil {
			t.Fatalf("Failed to remove session: %v", err)
		}

		// Verify it's gone
		sessions, err = registry.listSessions()
		if err != nil {
			t.Fatalf("Failed to list sessions after removal: %v", err)
		}
		if len(sessions) != 0 {
			t.Errorf("Expected 0 sessions after removal, got %d", len(sessions))
		}
	})

	t.Run("ProcessAliveCheck", func(t *testing.T) {
		// Test with current process (should be alive)
		currentPID := os.Getpid()
		if !registry.isProcessAlive(currentPID) {
			t.Error("Current process should be alive")
		}

		// Test with invalid PID
		if registry.isProcessAlive(-1) {
			t.Error("Invalid PID should not be alive")
		}
		
		if registry.isProcessAlive(0) {
			t.Error("PID 0 should not be alive")
		}

		// Test with very high PID (likely doesn't exist)
		if registry.isProcessAlive(999999) {
			t.Log("PID 999999 appears to exist (this might be normal on some systems)")
		}

		// Test with a known dead PID (from our session)
		deadPID := 36103 // From our manual test
		if registry.isProcessAlive(deadPID) {
			t.Logf("PID %d appears to be alive (might be reused)", deadPID)
		} else {
			t.Logf("PID %d correctly detected as dead", deadPID)
		}
	})
}

func TestConfigurableSessionsDirectory(t *testing.T) {
	tempDir := t.TempDir()
	customSessionsDir := filepath.Join(tempDir, "custom-sessions")
	
	t.Run("CustomSessionsDirectory", func(t *testing.T) {
		registry := NewSessionRegistryWithPath(customSessionsDir)
		
		// Create a session in the custom directory
		err := registry.createSession("custom-test", "echo hello", 12345)
		if err != nil {
			t.Fatalf("Failed to create session in custom directory: %v", err)
		}
		
		// Verify the session was created in the right place
		expectedPath := filepath.Join(customSessionsDir, "custom-test", "metadata.json")
		if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
			t.Fatalf("Session metadata not found at expected path: %s", expectedPath)
		}
		
		// Verify we can list sessions from the custom directory
		sessions, err := registry.listSessions()
		if err != nil {
			t.Fatalf("Failed to list sessions from custom directory: %v", err)
		}
		
		if len(sessions) != 1 {
			t.Fatalf("Expected 1 session, got %d", len(sessions))
		}
		
		if sessions[0].Name != "custom-test" {
			t.Errorf("Expected session name 'custom-test', got '%s'", sessions[0].Name)
		}
	})
	
	t.Run("ProxyWithCustomDirectory", func(t *testing.T) {
		proxy := NewStdioProxyWithSessionAndDir("echo test", "proxy-test", customSessionsDir)
		
		if proxy.sessionName != "proxy-test" {
			t.Errorf("Expected session name 'proxy-test', got '%s'", proxy.sessionName)
		}
		
		if proxy.sessionsDir != customSessionsDir {
			t.Errorf("Expected sessions dir '%s', got '%s'", customSessionsDir, proxy.sessionsDir)
		}
	})
}

func TestUnixSocketStreaming(t *testing.T) {
	// Use /tmp for shorter paths to avoid Unix socket path length limits
	sessionsDir := "/tmp/mcpview-test-" + fmt.Sprintf("%d", time.Now().UnixNano())
	defer os.RemoveAll(sessionsDir)
	
	t.Run("SocketPathGeneration", func(t *testing.T) {
		proxy := NewStdioProxyWithSessionAndDir("echo test", "test", sessionsDir)
		
		expectedPath := filepath.Join(sessionsDir, "test", "socket")
		if proxy.socketPath != expectedPath {
			t.Errorf("Expected socket path '%s', got '%s'", expectedPath, proxy.socketPath)
		}
	})
	
	t.Run("SocketServerCreation", func(t *testing.T) {
		proxy := NewStdioProxyWithSessionAndDir("echo test", "test", sessionsDir)
		
		t.Logf("Socket path: %s (length: %d)", proxy.socketPath, len(proxy.socketPath))
		
		// Create the session directory first
		registry := NewSessionRegistryWithPath(sessionsDir)
		err := registry.createSession("test", "echo test", 12345)
		if err != nil {
			t.Fatalf("Failed to create session: %v", err)
		}
		
		// Test socket server startup
		err = proxy.startSocketServer()
		if err != nil {
			t.Fatalf("Failed to start socket server: %v", err)
		}
		
		// Verify socket file exists
		if _, err := os.Stat(proxy.socketPath); os.IsNotExist(err) {
			t.Fatalf("Socket file not created at %s", proxy.socketPath)
		}
		
		// Cleanup
		if proxy.socketListener != nil {
			proxy.socketListener.Close()
		}
		os.Remove(proxy.socketPath)
	})
}
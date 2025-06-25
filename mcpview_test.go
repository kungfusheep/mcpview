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

func TestIsAlphaOnly(t *testing.T) {
	tests := []struct {
		input    string
		expected bool
	}{
		{"hello", true},
		{"world", true},
		{"abc", true},
		{"", true}, // empty string should be considered alpha-only
		{"hello123", false},
		{"hello-world", false},
		{"hello_world", false},
		{"Hello", false}, // uppercase not allowed
		{"test@example", false},
		{"test.com", false},
		{"test/path", false},
		{"café", false}, // non-ASCII not allowed
	}

	for _, test := range tests {
		t.Run(fmt.Sprintf("isAlphaOnly_%s", test.input), func(t *testing.T) {
			result := isAlphaOnly(test.input)
			if result != test.expected {
				t.Errorf("isAlphaOnly(%q) = %v, expected %v", test.input, result, test.expected)
			}
		})
	}
}

func TestReadWordList(t *testing.T) {
	t.Run("ValidWordList", func(t *testing.T) {
		// Create a temporary word list file
		tempFile := filepath.Join(t.TempDir(), "words")
		content := "apple\nbanana\ncat\ndog\nelephant\nverylongwordthatshouldbeskipped\ntest123\nvalid\n\n  \nword\n"
		err := os.WriteFile(tempFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test word file: %v", err)
		}

		words, err := readWordList(tempFile)
		if err != nil {
			t.Fatalf("readWordList failed: %v", err)
		}

		expectedWords := []string{"apple", "banana", "cat", "dog", "elephant", "valid", "word"}
		if len(words) != len(expectedWords) {
			t.Errorf("Expected %d words, got %d. Words: %v", len(expectedWords), len(words), words)
		}

		// Check that all expected words are present
		wordMap := make(map[string]bool)
		for _, word := range words {
			wordMap[word] = true
		}

		for _, expected := range expectedWords {
			if !wordMap[expected] {
				t.Errorf("Expected word %q not found in result", expected)
			}
		}

		// Verify filtering worked (no long words, no numbers, no empty)
		for _, word := range words {
			if len(word) < 3 || len(word) > 8 {
				t.Errorf("Word %q has invalid length %d (should be 3-8)", word, len(word))
			}
			if !isAlphaOnly(word) {
				t.Errorf("Word %q is not alpha-only", word)
			}
		}
	})

	t.Run("NonexistentFile", func(t *testing.T) {
		_, err := readWordList("/nonexistent/path/words")
		if err == nil {
			t.Error("Expected error for nonexistent file, got nil")
		}
	})

	t.Run("EmptyFile", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "empty")
		err := os.WriteFile(tempFile, []byte(""), 0644)
		if err != nil {
			t.Fatalf("Failed to create empty file: %v", err)
		}

		_, err = readWordList(tempFile)
		if err == nil {
			t.Error("Expected error for empty word list, got nil")
		}
	})

	t.Run("NoValidWords", func(t *testing.T) {
		tempFile := filepath.Join(t.TempDir(), "invalid")
		content := "ab\nverylongwordthatshouldbeskipped\ntest123\n@#$%\n"
		err := os.WriteFile(tempFile, []byte(content), 0644)
		if err != nil {
			t.Fatalf("Failed to create test file: %v", err)
		}

		_, err = readWordList(tempFile)
		if err == nil {
			t.Error("Expected error for no valid words, got nil")
		}
	})
}

func TestLoadSystemWords(t *testing.T) {
	t.Run("LoadSystemWords", func(t *testing.T) {
		// This test checks if system words can be loaded
		// It may pass or fail depending on the system, but shouldn't crash
		words, err := loadSystemWords()
		
		if err != nil {
			// It's OK if no system word list is found
			t.Logf("No system word list found (this is OK): %v", err)
			return
		}

		// If we found system words, verify they meet our criteria
		if len(words) == 0 {
			t.Error("System words loaded but empty list returned")
		}

		// Check a sample of words to ensure they're valid
		sampleSize := 10
		if len(words) < sampleSize {
			sampleSize = len(words)
		}

		for i := 0; i < sampleSize; i++ {
			word := words[i]
			if len(word) < 3 || len(word) > 8 {
				t.Errorf("System word %q has invalid length %d", word, len(word))
			}
			if !isAlphaOnly(word) {
				t.Errorf("System word %q is not alpha-only", word)
			}
		}

		t.Logf("Successfully loaded %d system words", len(words))
	})
}

func TestGenerateRandomSessionName(t *testing.T) {
	t.Run("GenerateRandomSessionName", func(t *testing.T) {
		// Generate multiple session names to test
		names := make(map[string]bool)
		for i := 0; i < 5; i++ {
			name := generateRandomSessionName()
			
			// Check basic format: word1-word2-MMDD-HHMM
			parts := fmt.Sprintf("%s", name)
			if parts == "" {
				t.Error("Generated empty session name")
			}

			// Session name should be unique each time (with high probability)
			if names[name] {
				t.Errorf("Generated duplicate session name: %s", name)
			}
			names[name] = true

			t.Logf("Generated session name: %s", name)

			// Verify format has at least 3 parts (word1-word2-timestamp)
			hyphenCount := 0
			for _, char := range name {
				if char == '-' {
					hyphenCount++
				}
			}
			if hyphenCount < 2 {
				t.Errorf("Session name %q should have at least 2 hyphens", name)
			}

			// Session name should be reasonable length
			if len(name) < 10 || len(name) > 50 {
				t.Errorf("Session name %q has unusual length %d", name, len(name))
			}
		}
	})

	t.Run("SessionNameUniqueness", func(t *testing.T) {
		// Generate many names quickly to test uniqueness
		names := make(map[string]bool)
		duplicates := 0
		
		for i := 0; i < 100; i++ {
			name := generateRandomSessionName()
			if names[name] {
				duplicates++
			}
			names[name] = true
			
			// Small delay to ensure different timestamps
			time.Sleep(time.Millisecond)
		}

		// Some duplicates might occur due to timestamp granularity, but should be rare
		if duplicates > 5 {
			t.Errorf("Too many duplicate session names: %d out of 100", duplicates)
		}

		t.Logf("Generated 100 session names with %d duplicates", duplicates)
	})
}

func TestSessionNameIntegration(t *testing.T) {
	t.Run("SessionNameGeneration", func(t *testing.T) {
		// Test that session creation with auto-generated names works
		tempDir := t.TempDir()
		registry := &SessionRegistry{basePath: tempDir}
		
		// Test with explicit session name
		explicitName := "my-test-session"
		err := registry.createSession(explicitName, "echo test", 12345)
		if err != nil {
			t.Fatalf("Failed to create session with explicit name: %v", err)
		}
		
		// Test with auto-generated session name
		autoName := generateRandomSessionName()
		err = registry.createSession(autoName, "echo test", 12346)
		if err != nil {
			t.Fatalf("Failed to create session with auto-generated name: %v", err)
		}
		
		// Verify both sessions exist
		sessions, err := registry.listSessions()
		if err != nil {
			t.Fatalf("Failed to list sessions: %v", err)
		}
		
		if len(sessions) != 2 {
			t.Fatalf("Expected 2 sessions, got %d", len(sessions))
		}
		
		// Find the sessions by name
		foundExplicit := false
		foundAuto := false
		for _, session := range sessions {
			if session.Name == explicitName {
				foundExplicit = true
			}
			if session.Name == autoName {
				foundAuto = true
			}
		}
		
		if !foundExplicit {
			t.Errorf("Explicit session %q not found", explicitName)
		}
		if !foundAuto {
			t.Errorf("Auto-generated session %q not found", autoName)
		}
		
		t.Logf("Successfully created sessions: %q and %q", explicitName, autoName)
	})
	
	t.Run("SessionNameValidation", func(t *testing.T) {
		// Test that empty session names are handled
		tempDir := t.TempDir()
		registry := &SessionRegistry{basePath: tempDir}
		
		err := registry.createSession("", "echo test", 12345)
		if err == nil {
			t.Error("Expected error for empty session name, got nil")
		}
	})
}
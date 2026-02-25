package engine_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/drogonsec/drogonsec/internal/engine"
)

func TestEngine_PythonSQLInjection(t *testing.T) {
	e := engine.New()

	// Create temp file with vulnerable code
	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "app.py")
	content := `
import sqlite3

def get_user(user_id):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    # VULNERABLE: SQL injection
    cursor.execute("SELECT * FROM users WHERE id = " + user_id)
    return cursor.fetchone()
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	if len(findings) == 0 {
		t.Error("Expected SQL injection finding, got none")
		return
	}

	found := false
	for _, f := range findings {
		if f.RuleID == "PY-001" {
			found = true
			if f.CWE != "CWE-89" {
				t.Errorf("Expected CWE-89, got %s", f.CWE)
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected PY-001 (SQL Injection) rule, got rules: %v", getRuleIDs(findings))
	}
}

func TestEngine_PythonPickleDeser(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "deserialize.py")
	content := `
import pickle
import base64

def load_session(data):
    # VULNERABLE: arbitrary code execution via pickle
    session = pickle.loads(base64.b64decode(data))
    return session
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "PY-007" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected PY-007 (Pickle deserialization) finding")
	}
}

func TestEngine_JavaHardcodedPassword(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "Config.java")
	content := `
public class Config {
    private static final String DATABASE_PASSWORD = "super_secret_password123";
    private static final String API_KEY = "my-production-api-key";
    
    public String getPassword() {
        return DATABASE_PASSWORD;
    }
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "JAVA-003" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected JAVA-003 (Hardcoded password) finding, got: %v", getRuleIDs(findings))
	}
}

func TestEngine_JSEval(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "app.js")
	content := `
function processInput(userInput) {
    // VULNERABLE: code injection
    const result = eval(userInput);
    return result;
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "JS-001" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected JS-001 (eval) finding, got: %v", getRuleIDs(findings))
	}
}

func TestEngine_GoTLSVerifyDisabled(t *testing.T) {
	e := engine.New()

	tmpDir := t.TempDir()
	vulnFile := filepath.Join(tmpDir, "client.go")
	content := `
package main

import (
    "crypto/tls"
    "net/http"
)

func createInsecureClient() *http.Client {
    tr := &http.Transport{
        TLSClientConfig: &tls.Config{
            InsecureSkipVerify: true, // VULNERABLE
        },
    }
    return &http.Client{Transport: tr}
}
`
	if err := os.WriteFile(vulnFile, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	findings := e.Analyze(vulnFile)

	found := false
	for _, f := range findings {
		if f.RuleID == "GO-005" {
			found = true
			break
		}
	}

	if !found {
		t.Errorf("Expected GO-005 (InsecureSkipVerify) finding, got: %v", getRuleIDs(findings))
	}
}

func TestEngine_RuleCount(t *testing.T) {
	e := engine.New()
	count := e.RuleCount()
	if count < 50 {
		t.Errorf("Expected at least 50 rules, got %d", count)
	}
	t.Logf("Total rules loaded: %d", count)
}

// helper
func getRuleIDs(findings []engine.Finding) []string {
	ids := make([]string, len(findings))
	for i, f := range findings {
		ids[i] = f.RuleID
	}
	return ids
}

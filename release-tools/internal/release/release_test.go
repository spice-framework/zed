package release

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const testCommit = "0123456789abcdef0123456789abcdef01234567"

func TestPackageSignVerify(t *testing.T) {
	root := newTestRepository(t)
	epoch := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	input := filepath.Join(root, "spice_zed.wasm")
	wasm := append([]byte("\x00asm\x01\x00\x00\x00"), []byte("deterministic fixture")...)
	writeTestFile(t, input, wasm)
	unsigned := filepath.Join(root, "unsigned")
	options := Options{Root: root, Input: input, Output: unsigned, Version: "v0.2.0", Commit: testCommit, Epoch: epoch.Unix()}
	if err := Package(options); err != nil {
		t.Fatalf("Package: %v", err)
	}
	second := filepath.Join(root, "unsigned-second")
	options.Output = second
	if err := Package(options); err != nil {
		t.Fatalf("Package second: %v", err)
	}
	assertDirectoriesEqual(t, unsigned, second)
	assertZedArchive(t, filepath.Join(unsigned, "spice-test_0.2.0.zip"), epoch, wasm)

	public, privateKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(root, publicKeyPath), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER}))
	privateDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(signingKeyEnv, base64.StdEncoding.EncodeToString(privateDER))
	signed := filepath.Join(root, "signed")
	options.Input, options.Output = unsigned, signed
	if err := Sign(options); err != nil {
		t.Fatalf("Sign: %v", err)
	}
	options.Input = signed
	result, err := Verify(options)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if result.Artifacts != 6 || result.Commit != testCommit || result.Version != "v0.2.0" {
		t.Fatalf("unexpected result: %+v", result)
	}

	signature := filepath.Join(signed, "checksums.txt.sig")
	corrupt := readTestFile(t, signature)
	corrupt[0] ^= 0xff
	if err := os.WriteFile(signature, corrupt, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(options); err == nil || !strings.Contains(err.Error(), "invalid Ed25519") {
		t.Fatalf("Verify corrupt signature error = %v", err)
	}
}

func TestPackageRejectsInvalidWASMAndMismatchedVersion(t *testing.T) {
	t.Parallel()
	root := newTestRepository(t)
	input := filepath.Join(root, "invalid.wasm")
	writeTestFile(t, input, []byte("not wasm"))
	options := Options{Root: root, Input: input, Output: filepath.Join(root, "out"), Version: "v0.2.0", Commit: testCommit, Epoch: 1_786_016_400}
	if err := Package(options); err == nil || !strings.Contains(err.Error(), "not a supported WebAssembly") {
		t.Fatalf("Package invalid WASM error = %v", err)
	}
	writeTestFile(t, input, []byte("\x00asm\x01\x00\x00\x00"))
	options.Version = "v0.2.1"
	if err := Package(options); err == nil || !strings.Contains(err.Error(), "does not match declared") {
		t.Fatalf("Package mismatched version error = %v", err)
	}
	writeTestFile(t, filepath.Join(root, "extension.toml"), []byte("version = \"0.2.0\"\nversion = \"0.2.0\"\n"))
	options.Version = "v0.2.0"
	if err := Package(options); err == nil || !strings.Contains(err.Error(), "exactly once") {
		t.Fatalf("Package duplicate version error = %v", err)
	}
}

func TestSignRejectsWrongKeyAndExtraArtifact(t *testing.T) {
	root := newTestRepository(t)
	input := filepath.Join(root, "spice_zed.wasm")
	writeTestFile(t, input, []byte("\x00asm\x01\x00\x00\x00"))
	unsigned := filepath.Join(root, "unsigned")
	options := Options{Root: root, Input: input, Output: unsigned, Version: "v0.2.0", Commit: testCommit, Epoch: 1_786_016_400}
	if err := Package(options); err != nil {
		t.Fatal(err)
	}
	_, trustedPrivate, _ := ed25519.GenerateKey(nil)
	trustedDER, _ := x509.MarshalPKIXPublicKey(trustedPrivate.Public())
	writeTestFile(t, filepath.Join(root, publicKeyPath), pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: trustedDER}))
	_, wrongPrivate, _ := ed25519.GenerateKey(nil)
	wrongDER, _ := x509.MarshalPKCS8PrivateKey(wrongPrivate)
	t.Setenv(signingKeyEnv, base64.StdEncoding.EncodeToString(wrongDER))
	options.Input, options.Output = unsigned, filepath.Join(root, "signed")
	if err := Sign(options); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("Sign wrong key error = %v", err)
	}
	writeTestFile(t, filepath.Join(unsigned, "unexpected"), []byte("no"))
	if err := Sign(options); err == nil || !strings.Contains(err.Error(), "artifact names") {
		t.Fatalf("Sign extra artifact error = %v", err)
	}
}

func TestPackageRejectsUnsafeConfigurationPaths(t *testing.T) {
	t.Parallel()
	root := newTestRepository(t)
	writeTestFile(t, filepath.Join(root, configPath), []byte(`{
  "schema": 1,
  "repository": "spice-framework/test-editor",
  "artifactBase": "spice-test",
  "displayName": "Spice Test Editor",
  "kind": "zed",
  "versionFile": "../extension.toml",
  "versionKey": "version"
}
`))
	input := filepath.Join(root, "spice_zed.wasm")
	writeTestFile(t, input, []byte("\x00asm\x0d\x00\x01\x00"))
	options := Options{Root: root, Input: input, Output: filepath.Join(root, "out"), Version: "v0.2.0", Commit: testCommit, Epoch: 1_786_016_400}
	if err := Package(options); err == nil || !strings.Contains(err.Error(), "schema 1") {
		t.Fatalf("Package unsafe config error = %v", err)
	}
}

func newTestRepository(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writeTestFile(t, filepath.Join(root, configPath), []byte(`{
  "schema": 1,
  "repository": "spice-framework/test-editor",
  "artifactBase": "spice-test",
  "displayName": "Spice Test Editor",
  "kind": "zed",
  "versionFile": "extension.toml",
  "versionKey": "version"
}
`))
	writeTestFile(t, filepath.Join(root, "extension.toml"), []byte("version = \"0.2.0\"\nname = \"Spice Test\"\n"))
	writeTestFile(t, filepath.Join(root, "LICENSE"), []byte("test Apache-2.0 license\n"))
	return root
}

func assertZedArchive(t *testing.T, name string, epoch time.Time, wasm []byte) {
	t.Helper()
	reader, err := zip.OpenReader(name)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	want := map[string][]byte{
		"spice/LICENSE":        []byte("test Apache-2.0 license\n"),
		"spice/extension.toml": []byte("version = \"0.2.0\"\nname = \"Spice Test\"\n"),
		"spice/extension.wasm": wasm,
	}
	if len(reader.File) != len(want) {
		t.Fatalf("archive contains %d entries, want %d", len(reader.File), len(want))
	}
	for _, entry := range reader.File {
		if !entry.Modified.Equal(epoch) {
			t.Fatalf("entry %s timestamp = %s, want %s", entry.Name, entry.Modified, epoch)
		}
		stream, err := entry.Open()
		if err != nil {
			t.Fatal(err)
		}
		content, err := io.ReadAll(stream)
		if err != nil {
			t.Fatal(err)
		}
		if err := stream.Close(); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(content, want[entry.Name]) {
			t.Fatalf("entry %s content differs", entry.Name)
		}
	}
}

func writeTestFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(name), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(name, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func readTestFile(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func assertDirectoriesEqual(t *testing.T, first, second string) {
	t.Helper()
	firstEntries, err := os.ReadDir(first)
	if err != nil {
		t.Fatal(err)
	}
	secondEntries, err := os.ReadDir(second)
	if err != nil {
		t.Fatal(err)
	}
	if len(firstEntries) != len(secondEntries) {
		t.Fatalf("entry counts differ: %d != %d", len(firstEntries), len(secondEntries))
	}
	for _, entry := range firstEntries {
		if !bytes.Equal(readTestFile(t, filepath.Join(first, entry.Name())), readTestFile(t, filepath.Join(second, entry.Name()))) {
			t.Fatalf("artifact %s differs", entry.Name())
		}
	}
}

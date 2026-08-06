package release

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const repositoryKeyFingerprint = "4c85bbb1d629601f472b5be1c8dd1596ae4ccb4e2d0add3843c1653d6c0594dd"

func TestRepositoryTrustAnchorIsCanonicalAndPinned(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, publicKeyPath))
	if err != nil {
		t.Fatal(err)
	}
	key, err := parsePublicKey(data)
	if err != nil {
		t.Fatal(err)
	}
	fingerprint := sha256.Sum256(key)
	if actual := hex.EncodeToString(fingerprint[:]); actual != repositoryKeyFingerprint {
		t.Fatalf("release key fingerprint = %s, want %s", actual, repositoryKeyFingerprint)
	}
}

func TestRepositoryReleaseWorkflowFailsClosed(t *testing.T) {
	t.Parallel()
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	data, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "release.yml"))
	if err != nil {
		t.Fatal(err)
	}
	workflow := string(data)
	requireWorkflowText(t, workflow,
		"permissions: {}",
		"GOTOOLCHAIN: \"local\"",
		"environment:\n      name: release-signing",
		"environment:\n      name: release-publish",
		"runs-on: windows-2025",
		"needs: [validate-source, verify-reproducibility]",
		"needs: [validate-source, independent-rebuild, verify-reproducibility, sign]",
		"needs: [validate-source, sign, verify-artifacts]",
		"SPICE_EDITOR_RELEASE_SIGNING_KEY: ${{ secrets.SPICE_EDITOR_RELEASE_SIGNING_KEY }}",
		"persist-credentials: false",
	)
	if count := strings.Count(workflow, "contents: write"); count != 1 {
		t.Fatalf("contents: write count = %d, want exactly one final publisher", count)
	}
	publish := strings.Index(workflow, "\n  publish:")
	write := strings.Index(workflow, "contents: write")
	if publish < 0 || write < publish {
		t.Fatal("contents: write is not confined to the publish job")
	}
	for _, forbidden := range []string{"pull_request_target:", "workflow_dispatch:", "workflow_run:", "secrets: inherit", "persist-credentials: true"} {
		if strings.Contains(workflow, forbidden) {
			t.Fatalf("release workflow contains forbidden %q", forbidden)
		}
	}
	pinned := regexp.MustCompile(`(?m)^\s+uses:\s+[^@\s]+@([0-9a-f]{40})(?:\s+#.*)?$`)
	usesLines := regexp.MustCompile(`(?m)^\s+uses:\s+.*$`).FindAllString(workflow, -1)
	if len(usesLines) == 0 || len(pinned.FindAllString(workflow, -1)) != len(usesLines) {
		t.Fatalf("every action must use an immutable 40-character commit: %v", usesLines)
	}
}

func requireWorkflowText(t *testing.T, workflow string, values ...string) {
	t.Helper()
	for _, value := range values {
		if !strings.Contains(workflow, value) {
			t.Errorf("release workflow lacks %q", value)
		}
	}
}

// Package release creates and authenticates deterministic Spice editor artifacts.
package release

import (
	"archive/zip"
	"bytes"
	"crypto/ed25519"
	"crypto/sha1" // SPDX 2.3 defines its package verification code as SHA-1.
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

const (
	configPath       = "release-tools/release.json"
	publicKeyPath    = "security/release/ed25519-public.pem"
	signingKeyEnv    = "SPICE_EDITOR_RELEASE_SIGNING_KEY"
	maxArtifactBytes = 128 << 20
)

var (
	versionPattern    = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$`)
	commitPattern     = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repositoryPattern = regexp.MustCompile(`^spice-framework/[a-z0-9][a-z0-9-]*$`)
	artifactPattern   = regexp.MustCompile(`^[a-z0-9][a-z0-9-]*$`)
	versionKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9]*$`)
)

type Options struct {
	Root    string
	Input   string
	Output  string
	Version string
	Commit  string
	Epoch   int64
}

type Result struct {
	Repository string
	Version    string
	Commit     string
	Artifacts  int
}

type config struct {
	Schema       int    `json:"schema"`
	Repository   string `json:"repository"`
	ArtifactBase string `json:"artifactBase"`
	DisplayName  string `json:"displayName"`
	Kind         string `json:"kind"`
	VersionFile  string `json:"versionFile"`
	VersionKey   string `json:"versionKey"`
}

type metadata struct {
	config config
	root   string
	base   string
	commit string
	epoch  time.Time
	names  artifactNames
}

type artifactNames struct {
	Package    string
	SBOM       string
	Provenance string
}

func Package(options Options) error {
	meta, err := validateOptions(options, true)
	if err != nil {
		return err
	}
	input, err := readRegular(options.Input, maxArtifactBytes)
	if err != nil {
		return fmt.Errorf("read package input: %w", err)
	}
	var packaged []byte
	switch meta.config.Kind {
	case "goland":
		packaged, err = normalizeZIP(input, meta.epoch)
	case "zed":
		packaged, err = packageZed(meta, input)
	default:
		err = fmt.Errorf("unsupported artifact kind %q", meta.config.Kind)
	}
	if err != nil {
		return fmt.Errorf("package %s: %w", meta.config.Kind, err)
	}
	files := map[string][]byte{meta.names.Package: packaged}
	files[meta.names.SBOM], err = renderSBOM(meta, packaged)
	if err != nil {
		return err
	}
	files[meta.names.Provenance], err = renderProvenance(meta, packaged)
	if err != nil {
		return err
	}
	files["checksums.txt"] = renderChecksums(files)
	if err := validateUnsigned(meta, files); err != nil {
		return fmt.Errorf("validate packaged artifacts: %w", err)
	}
	return writeNewDirectory(options.Output, files)
}

func Sign(options Options) error {
	meta, err := validateOptions(options, false)
	if err != nil {
		return err
	}
	files, err := readDirectory(options.Input, maxArtifactBytes)
	if err != nil {
		return fmt.Errorf("read unsigned artifacts: %w", err)
	}
	if err := validateUnsigned(meta, files); err != nil {
		return fmt.Errorf("refuse unsigned artifacts: %w", err)
	}
	privateKey, err := signingKeyFromEnvironment()
	if err != nil {
		return err
	}
	defer clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	trustedPEM, err := readRegular(filepath.Join(meta.root, publicKeyPath), 4096)
	if err != nil {
		return fmt.Errorf("read trusted public key: %w", err)
	}
	canonicalPEM, err := encodePublicKey(publicKey)
	if err != nil {
		return err
	}
	if !bytes.Equal(trustedPEM, canonicalPEM) {
		return errors.New("private signing key does not match committed trust anchor")
	}
	checksums := files["checksums.txt"]
	signature := ed25519.Sign(privateKey, checksums)
	if !ed25519.Verify(publicKey, checksums, signature) {
		return errors.New("self-verification of release signature failed")
	}
	files["checksums.txt.pem"] = canonicalPEM
	files["checksums.txt.sig"] = signature
	if err := validateSigned(meta, files, publicKey); err != nil {
		return fmt.Errorf("validate signed artifacts: %w", err)
	}
	return writeNewDirectory(options.Output, files)
}

func Verify(options Options) (Result, error) {
	meta, err := validateOptions(options, false)
	if err != nil {
		return Result{}, err
	}
	files, err := readDirectory(options.Input, maxArtifactBytes)
	if err != nil {
		return Result{}, fmt.Errorf("read signed artifacts: %w", err)
	}
	trustedPEM, err := readRegular(filepath.Join(meta.root, publicKeyPath), 4096)
	if err != nil {
		return Result{}, fmt.Errorf("read trusted public key: %w", err)
	}
	trusted, err := parsePublicKey(trustedPEM)
	if err != nil {
		return Result{}, err
	}
	if err := validateSigned(meta, files, trusted); err != nil {
		return Result{}, err
	}
	return Result{Repository: meta.config.Repository, Version: options.Version, Commit: options.Commit, Artifacts: len(files)}, nil
}

func validateOptions(options Options, requirePackageInput bool) (metadata, error) {
	root, err := filepath.Abs(options.Root)
	if err != nil {
		return metadata{}, fmt.Errorf("resolve repository root: %w", err)
	}
	data, err := readRegular(filepath.Join(root, configPath), 16<<10)
	if err != nil {
		return metadata{}, fmt.Errorf("read release configuration: %w", err)
	}
	var value config
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return metadata{}, fmt.Errorf("decode release configuration: %w", err)
	}
	if decoder.Decode(new(any)) != io.EOF {
		return metadata{}, errors.New("release configuration has trailing JSON")
	}
	if value.Schema != 1 || !repositoryPattern.MatchString(value.Repository) || !artifactPattern.MatchString(value.ArtifactBase) || strings.TrimSpace(value.DisplayName) != value.DisplayName || value.DisplayName == "" ||
		(value.Kind != "goland" && value.Kind != "zed") || !safeRelativePath(value.VersionFile) || !versionKeyPattern.MatchString(value.VersionKey) {
		return metadata{}, errors.New("release configuration does not match schema 1")
	}
	if !versionPattern.MatchString(options.Version) {
		return metadata{}, fmt.Errorf("version %q must be canonical vMAJOR.MINOR.PATCH", options.Version)
	}
	if !commitPattern.MatchString(options.Commit) {
		return metadata{}, fmt.Errorf("commit %q must be a lowercase full object ID", options.Commit)
	}
	if options.Epoch <= 0 {
		return metadata{}, errors.New("source date epoch must be positive")
	}
	if options.Output == "" || options.Input == "" {
		return metadata{}, errors.New("input and output paths are required")
	}
	if requirePackageInput {
		info, statErr := os.Stat(options.Input)
		if statErr != nil || !info.Mode().IsRegular() {
			return metadata{}, errors.New("package input must be a regular file")
		}
	}
	declared, err := declaredVersion(filepath.Join(root, value.VersionFile), value.VersionKey)
	if err != nil {
		return metadata{}, err
	}
	if options.Version != "v"+declared {
		return metadata{}, fmt.Errorf("tag version %s does not match declared version %s", options.Version, declared)
	}
	base := strings.TrimPrefix(options.Version, "v")
	return metadata{
		config: value, root: root, base: base, commit: options.Commit, epoch: time.Unix(options.Epoch, 0).UTC(),
		names: artifactNames{
			Package:    value.ArtifactBase + "_" + base + ".zip",
			SBOM:       value.ArtifactBase + "_" + base + "_sbom.spdx.json",
			Provenance: value.ArtifactBase + "_" + base + "_provenance.intoto.jsonl",
		},
	}, nil
}

func safeRelativePath(name string) bool {
	if name == "" || filepath.IsAbs(name) || strings.Contains(name, `\`) {
		return false
	}
	clean := path.Clean(name)
	return clean == name && clean != "." && clean != ".." && !strings.HasPrefix(clean, "../")
}

func declaredVersion(name, key string) (string, error) {
	data, err := readRegular(name, 1<<20)
	if err != nil {
		return "", fmt.Errorf("read declared version: %w", err)
	}
	var matches []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, key+"=") {
			matches = append(matches, strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, key+"=")), `"`))
		}
		if strings.HasPrefix(line, key+" = ") {
			matches = append(matches, strings.Trim(strings.TrimSpace(strings.TrimPrefix(line, key+" = ")), `"`))
		}
	}
	if len(matches) != 1 || matches[0] == "" {
		return "", fmt.Errorf("%s must declare %s exactly once", name, key)
	}
	return matches[0], nil
}

func packageZed(meta metadata, wasm []byte) ([]byte, error) {
	if !validWASMHeader(wasm) {
		return nil, errors.New("release input is not a supported WebAssembly module or component")
	}
	manifest, err := readRegular(filepath.Join(meta.root, "extension.toml"), 1<<20)
	if err != nil {
		return nil, err
	}
	license, err := readRegular(filepath.Join(meta.root, "LICENSE"), 1<<20)
	if err != nil {
		return nil, err
	}
	return createZIP(meta.epoch, map[string][]byte{
		"spice/LICENSE": license, "spice/extension.toml": manifest, "spice/extension.wasm": wasm,
	})
}

func normalizeZIP(data []byte, epoch time.Time) ([]byte, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return nil, err
	}
	entries := make(map[string][]byte, len(reader.File))
	for _, item := range reader.File {
		if err := validateArchiveName(item.Name); err != nil {
			return nil, err
		}
		if _, duplicate := entries[item.Name]; duplicate {
			return nil, fmt.Errorf("duplicate archive entry %q", item.Name)
		}
		if item.FileInfo().IsDir() {
			entries[item.Name] = nil
			continue
		}
		content, err := readZIPEntry(item, maxArtifactBytes)
		if err != nil {
			return nil, err
		}
		if (strings.HasSuffix(strings.ToLower(item.Name), ".jar") || strings.HasSuffix(strings.ToLower(item.Name), ".zip")) && bytes.HasPrefix(content, []byte("PK\x03\x04")) {
			content, err = normalizeZIP(content, epoch)
			if err != nil {
				return nil, fmt.Errorf("normalize nested archive %s: %w", item.Name, err)
			}
		}
		entries[item.Name] = content
	}
	return createZIP(epoch, entries)
}

func createZIP(epoch time.Time, entries map[string][]byte) ([]byte, error) {
	names := make([]string, 0, len(entries))
	for name := range entries {
		if err := validateArchiveName(name); err != nil {
			return nil, err
		}
		names = append(names, name)
	}
	slices.Sort(names)
	var buffer bytes.Buffer
	writer := zip.NewWriter(&buffer)
	for _, name := range names {
		header := &zip.FileHeader{Name: name, Method: zip.Deflate, Modified: epoch}
		if strings.HasSuffix(name, "/") {
			header.Method = zip.Store
			header.SetMode(fs.ModeDir | 0o755)
		} else {
			header.SetMode(0o644)
		}
		entry, err := writer.CreateHeader(header)
		if err != nil {
			return nil, err
		}
		if _, err := entry.Write(entries[name]); err != nil {
			return nil, err
		}
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return buffer.Bytes(), nil
}

func validateArchiveName(name string) error {
	if name == "" || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || path.Clean(name) != strings.TrimSuffix(name, "/") || strings.HasPrefix(path.Clean(name), "../") {
		return fmt.Errorf("unsafe archive entry %q", name)
	}
	return nil
}

func readZIPEntry(item *zip.File, limit int64) ([]byte, error) {
	if item.UncompressedSize64 > uint64(limit) {
		return nil, fmt.Errorf("archive entry %q exceeds size limit", item.Name)
	}
	reader, err := item.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("archive entry %q exceeds size limit", item.Name)
	}
	return data, nil
}

type spdxDocument struct {
	SPDXVersion       string             `json:"spdxVersion"`
	DataLicense       string             `json:"dataLicense"`
	SPDXID            string             `json:"SPDXID"`
	Name              string             `json:"name"`
	DocumentNamespace string             `json:"documentNamespace"`
	CreationInfo      spdxCreation       `json:"creationInfo"`
	Packages          []spdxPackage      `json:"packages"`
	Files             []spdxFile         `json:"files"`
	Relationships     []spdxRelationship `json:"relationships"`
}
type spdxCreation struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}
type spdxPackage struct {
	Name                    string            `json:"name"`
	SPDXID                  string            `json:"SPDXID"`
	VersionInfo             string            `json:"versionInfo"`
	DownloadLocation        string            `json:"downloadLocation"`
	FilesAnalyzed           bool              `json:"filesAnalyzed"`
	PackageVerificationCode map[string]string `json:"packageVerificationCode"`
	LicenseConcluded        string            `json:"licenseConcluded"`
	LicenseDeclared         string            `json:"licenseDeclared"`
	CopyrightText           string            `json:"copyrightText"`
}
type spdxFile struct {
	FileName         string         `json:"fileName"`
	SPDXID           string         `json:"SPDXID"`
	Checksums        []spdxChecksum `json:"checksums"`
	LicenseConcluded string         `json:"licenseConcluded"`
	CopyrightText    string         `json:"copyrightText"`
}
type spdxChecksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}
type spdxRelationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

func renderSBOM(meta metadata, artifact []byte) ([]byte, error) {
	sha256Sum := sha256.Sum256(artifact)
	fileSHA1 := sha1.Sum(artifact)
	verificationCode := sha1.Sum([]byte(hex.EncodeToString(fileSHA1[:])))
	namespace := sha256.Sum256([]byte(meta.config.Repository + "\n" + meta.base + "\n" + hex.EncodeToString(sha256Sum[:])))
	document := spdxDocument{
		SPDXVersion: "SPDX-2.3", DataLicense: "CC0-1.0", SPDXID: "SPDXRef-DOCUMENT",
		Name:              meta.config.DisplayName + " " + meta.base,
		DocumentNamespace: "https://github.com/" + meta.config.Repository + "/releases/v" + meta.base + "/spdx/" + hex.EncodeToString(namespace[:]),
		CreationInfo:      spdxCreation{Created: meta.epoch.Format(time.RFC3339), Creators: []string{"Organization: Spice Framework", "Tool: Spice editor-release/v1"}},
		Packages:          []spdxPackage{{Name: meta.config.DisplayName, SPDXID: "SPDXRef-Package", VersionInfo: meta.base, DownloadLocation: "NOASSERTION", FilesAnalyzed: true, PackageVerificationCode: map[string]string{"packageVerificationCodeValue": hex.EncodeToString(verificationCode[:])}, LicenseConcluded: "Apache-2.0", LicenseDeclared: "Apache-2.0", CopyrightText: "NOASSERTION"}},
		Files:             []spdxFile{{FileName: "./" + meta.names.Package, SPDXID: "SPDXRef-File-Artifact", Checksums: []spdxChecksum{{Algorithm: "SHA256", ChecksumValue: hex.EncodeToString(sha256Sum[:])}}, LicenseConcluded: "Apache-2.0", CopyrightText: "NOASSERTION"}},
		Relationships:     []spdxRelationship{{SPDXElementID: "SPDXRef-DOCUMENT", RelationshipType: "DESCRIBES", RelatedSPDXElement: "SPDXRef-Package"}, {SPDXElementID: "SPDXRef-Package", RelationshipType: "CONTAINS", RelatedSPDXElement: "SPDXRef-File-Artifact"}},
	}
	return canonicalJSON(document)
}

type statement struct {
	Type          string    `json:"_type"`
	Subject       []subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     predicate `json:"predicate"`
}
type subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}
type predicate struct {
	BuildDefinition buildDefinition `json:"buildDefinition"`
	RunDetails      runDetails      `json:"runDetails"`
}
type buildDefinition struct {
	BuildType            string               `json:"buildType"`
	ExternalParameters   map[string]string    `json:"externalParameters"`
	InternalParameters   map[string]int64     `json:"internalParameters"`
	ResolvedDependencies []resolvedDependency `json:"resolvedDependencies"`
}
type resolvedDependency struct {
	URI    string            `json:"uri"`
	Digest map[string]string `json:"digest"`
}
type runDetails struct {
	Builder  map[string]string `json:"builder"`
	Metadata map[string]bool   `json:"metadata"`
}

func renderProvenance(meta metadata, artifact []byte) ([]byte, error) {
	sum := sha256.Sum256(artifact)
	buildType := "https://github.com/" + meta.config.Repository + "/release-tools/editor-release/v1"
	builder := "https://github.com/" + meta.config.Repository + "/.github/workflows/release.yml@refs/tags/v" + meta.base
	value := statement{
		Type: "https://in-toto.io/Statement/v1", Subject: []subject{{Name: meta.names.Package, Digest: map[string]string{"sha256": hex.EncodeToString(sum[:])}}}, PredicateType: "https://slsa.dev/provenance/v1",
		Predicate: predicate{BuildDefinition: buildDefinition{BuildType: buildType, ExternalParameters: map[string]string{"repository": meta.config.Repository, "version": "v" + meta.base}, InternalParameters: map[string]int64{"sourceDateEpoch": meta.epoch.Unix()}, ResolvedDependencies: []resolvedDependency{{URI: "git+https://github.com/" + meta.config.Repository + "@refs/tags/v" + meta.base, Digest: map[string]string{"gitCommit": meta.commit}}}}, RunDetails: runDetails{Builder: map[string]string{"id": builder}, Metadata: map[string]bool{"reproducible": true}}},
	}
	return canonicalJSONLine(value)
}

func canonicalJSON(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}
func canonicalJSONLine(value any) ([]byte, error) {
	data, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func renderChecksums(files map[string][]byte) []byte {
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	var result strings.Builder
	for _, name := range names {
		sum := sha256.Sum256(files[name])
		fmt.Fprintf(&result, "%x  %s\n", sum, name)
	}
	return []byte(result.String())
}

func validateUnsigned(meta metadata, files map[string][]byte) error {
	want := []string{"checksums.txt", meta.names.Package, meta.names.Provenance, meta.names.SBOM}
	if err := exactNames(files, want); err != nil {
		return err
	}
	if !bytes.Equal(files["checksums.txt"], renderChecksums(map[string][]byte{meta.names.Package: files[meta.names.Package], meta.names.Provenance: files[meta.names.Provenance], meta.names.SBOM: files[meta.names.SBOM]})) {
		return errors.New("checksums.txt is not canonical or does not authenticate exact artifacts")
	}
	expectedSBOM, err := renderSBOM(meta, files[meta.names.Package])
	if err != nil {
		return err
	}
	if !bytes.Equal(files[meta.names.SBOM], expectedSBOM) {
		return errors.New("SBOM does not match artifact identity")
	}
	expectedProvenance, err := renderProvenance(meta, files[meta.names.Package])
	if err != nil {
		return err
	}
	if !bytes.Equal(files[meta.names.Provenance], expectedProvenance) {
		return errors.New("provenance does not match artifact identity")
	}
	return validatePackage(meta, files[meta.names.Package])
}

func validateSigned(meta metadata, files map[string][]byte, trusted ed25519.PublicKey) error {
	want := []string{"checksums.txt", "checksums.txt.pem", "checksums.txt.sig", meta.names.Package, meta.names.Provenance, meta.names.SBOM}
	if err := exactNames(files, want); err != nil {
		return err
	}
	unsigned := make(map[string][]byte, 4)
	for _, name := range []string{"checksums.txt", meta.names.Package, meta.names.Provenance, meta.names.SBOM} {
		unsigned[name] = files[name]
	}
	if err := validateUnsigned(meta, unsigned); err != nil {
		return err
	}
	emitted, err := parsePublicKey(files["checksums.txt.pem"])
	if err != nil {
		return err
	}
	if !bytes.Equal(emitted, trusted) {
		return errors.New("emitted public key does not match committed trust anchor")
	}
	if len(files["checksums.txt.sig"]) != ed25519.SignatureSize || !ed25519.Verify(trusted, files["checksums.txt"], files["checksums.txt.sig"]) {
		return errors.New("invalid Ed25519 checksum signature")
	}
	return nil
}

func validatePackage(meta metadata, data []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	contents := map[string][]byte{}
	hasPluginXML := false
	for _, item := range reader.File {
		if err := validateArchiveName(item.Name); err != nil {
			return err
		}
		if seen[item.Name] {
			return fmt.Errorf("duplicate package entry %q", item.Name)
		}
		seen[item.Name] = true
		if !item.Modified.Equal(meta.epoch) {
			return fmt.Errorf("package entry %q has nondeterministic timestamp", item.Name)
		}
		if item.Mode()&fs.ModeSymlink != 0 {
			return fmt.Errorf("package entry %q is a symbolic link", item.Name)
		}
		if meta.config.Kind == "zed" && !item.FileInfo().IsDir() {
			content, readErr := readZIPEntry(item, maxArtifactBytes)
			if readErr != nil {
				return readErr
			}
			contents[item.Name] = content
		}
		if strings.HasSuffix(item.Name, "META-INF/plugin.xml") {
			hasPluginXML = true
		}
		if !item.FileInfo().IsDir() && strings.HasSuffix(strings.ToLower(item.Name), ".jar") {
			content, readErr := readZIPEntry(item, maxArtifactBytes)
			if readErr != nil {
				return readErr
			}
			contains, inspectErr := zipContainsSuffix(content, "META-INF/plugin.xml")
			if inspectErr != nil {
				return fmt.Errorf("inspect plugin archive %s: %w", item.Name, inspectErr)
			}
			hasPluginXML = hasPluginXML || contains
		}
	}
	if meta.config.Kind == "goland" && !hasPluginXML {
		return errors.New("GoLand package lacks META-INF/plugin.xml")
	}
	if meta.config.Kind == "zed" {
		want := []string{"spice/LICENSE", "spice/extension.toml", "spice/extension.wasm"}
		actual := make([]string, 0, len(seen))
		for name := range seen {
			actual = append(actual, name)
		}
		slices.Sort(actual)
		if !slices.Equal(actual, want) {
			return fmt.Errorf("Zed package entries %v do not match %v", actual, want)
		}
		manifest, err := readRegular(filepath.Join(meta.root, "extension.toml"), 1<<20)
		if err != nil {
			return err
		}
		license, err := readRegular(filepath.Join(meta.root, "LICENSE"), 1<<20)
		if err != nil {
			return err
		}
		if !bytes.Equal(contents["spice/extension.toml"], manifest) {
			return errors.New("Zed package manifest does not match repository source")
		}
		if !bytes.Equal(contents["spice/LICENSE"], license) {
			return errors.New("Zed package license does not match repository source")
		}
		wasm := contents["spice/extension.wasm"]
		if !validWASMHeader(wasm) {
			return errors.New("Zed package does not contain a supported WebAssembly module or component")
		}
	}
	return nil
}

func validWASMHeader(data []byte) bool {
	if len(data) < 8 || !bytes.Equal(data[:4], []byte("\x00asm")) {
		return false
	}
	version := data[4:8]
	return bytes.Equal(version, []byte("\x01\x00\x00\x00")) || // Core WebAssembly module version 1.
		bytes.Equal(version, []byte("\x0d\x00\x01\x00")) // Component Model binary version used by wasm32-wasip2.
}

func zipContainsSuffix(data []byte, suffix string) (bool, error) {
	reader, err := zip.NewReader(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		return false, err
	}
	for _, item := range reader.File {
		if err := validateArchiveName(item.Name); err != nil {
			return false, err
		}
		if strings.HasSuffix(item.Name, suffix) {
			return true, nil
		}
	}
	return false, nil
}

func exactNames(files map[string][]byte, want []string) error {
	actual := make([]string, 0, len(files))
	for name := range files {
		actual = append(actual, name)
	}
	slices.Sort(actual)
	slices.Sort(want)
	if !slices.Equal(actual, want) {
		return fmt.Errorf("artifact names %v do not match %v", actual, want)
	}
	return nil
}

func signingKeyFromEnvironment() (ed25519.PrivateKey, error) {
	encoded := os.Getenv(signingKeyEnv)
	if encoded == "" {
		return nil, fmt.Errorf("%s is required", signingKeyEnv)
	}
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("decode signing key: %w", err)
	}
	if block, _ := pem.Decode(data); block != nil {
		data = block.Bytes
	}
	if parsed, parseErr := x509.ParsePKCS8PrivateKey(data); parseErr == nil {
		key, ok := parsed.(ed25519.PrivateKey)
		if !ok {
			return nil, errors.New("signing key is not Ed25519")
		}
		return append(ed25519.PrivateKey(nil), key...), nil
	}
	if len(data) == ed25519.SeedSize {
		return ed25519.NewKeyFromSeed(data), nil
	}
	return nil, errors.New("signing key must be base64 PKCS#8 Ed25519 or a 32-byte seed")
}

func parsePublicKey(data []byte) (ed25519.PublicKey, error) {
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("public key is not one canonical PEM block")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(ed25519.PublicKey)
	if !ok || len(key) != ed25519.PublicKeySize {
		return nil, errors.New("public key is not Ed25519")
	}
	canonical, err := encodePublicKey(key)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(data, canonical) {
		return nil, errors.New("public key PEM is not canonical")
	}
	return append(ed25519.PublicKey(nil), key...), nil
}
func encodePublicKey(key ed25519.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), nil
}

func readRegular(name string, limit int64) ([]byte, error) {
	info, err := os.Lstat(name)
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("not a regular file")
	}
	if info.Size() > limit {
		return nil, fmt.Errorf("file exceeds %d bytes", limit)
	}
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("file exceeds size limit")
	}
	return data, nil
}
func readDirectory(directory string, limit int64) (map[string][]byte, error) {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return nil, err
	}
	files := make(map[string][]byte, len(entries))
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&fs.ModeSymlink != 0 || filepath.Base(entry.Name()) != entry.Name() {
			return nil, fmt.Errorf("unexpected non-file artifact %q", entry.Name())
		}
		data, err := readRegular(filepath.Join(directory, entry.Name()), limit)
		if err != nil {
			return nil, err
		}
		files[entry.Name()] = data
	}
	return files, nil
}
func writeNewDirectory(directory string, files map[string][]byte) error {
	if directory == "" {
		return errors.New("output directory is required")
	}
	if _, err := os.Lstat(directory); !errors.Is(err, fs.ErrNotExist) {
		return errors.New("output directory already exists")
	}
	parent := filepath.Dir(directory)
	staging, err := os.MkdirTemp(parent, ".editor-release-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(staging)
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if filepath.Base(name) != name {
			return errors.New("unsafe artifact name")
		}
		if err := os.WriteFile(filepath.Join(staging, name), files[name], 0o644); err != nil {
			return err
		}
	}
	return os.Rename(staging, directory)
}

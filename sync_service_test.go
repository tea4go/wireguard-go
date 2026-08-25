package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestReadSyncTunnelsFromConfAndZip(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "office.conf")
	confBody := "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x21) + "\n"
	if err := os.WriteFile(confPath, []byte(confBody), 0o644); err != nil {
		t.Fatalf("WriteFile(conf): %v", err)
	}

	tunnels, err := readSyncTunnels(confPath)
	if err != nil {
		t.Fatalf("readSyncTunnels(conf): %v", err)
	}

	if got, want := tunnels, []syncTunnel{{Name: "office", Content: confBody}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected conf tunnels:\nwant: %#v\ngot:  %#v", want, got)
	}

	zipPath := filepath.Join(dir, "bundle.zip")
	file, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create(zip): %v", err)
	}
	zw := zip.NewWriter(file)
	files := map[string]string{
		"b.conf":        "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x22) + "\n",
		"folder/a.conf": "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x23) + "\n",
		"notes.txt":     "ignore",
	}
	for name, body := range files {
		w, err := zw.Create(name)
		if err != nil {
			t.Fatalf("Create(%q): %v", name, err)
		}
		if _, err := w.Write([]byte(body)); err != nil {
			t.Fatalf("Write(%q): %v", name, err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatalf("Close(zip): %v", err)
	}
	if err := file.Close(); err != nil {
		t.Fatalf("Close(file): %v", err)
	}

	tunnels, err = readSyncTunnels(zipPath)
	if err != nil {
		t.Fatalf("readSyncTunnels(zip): %v", err)
	}

	wantZip := []syncTunnel{
		{Name: "a", Content: files["folder/a.conf"]},
		{Name: "b", Content: files["b.conf"]},
	}
	if !reflect.DeepEqual(tunnels, wantZip) {
		t.Fatalf("unexpected zip tunnels:\nwant: %#v\ngot:  %#v", wantZip, tunnels)
	}
}

func TestReadSyncTunnelsFromDirectory(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"b.conf":    "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x2d) + "\n",
		"a.conf":    "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x2e) + "\n",
		"notes.txt": "ignore",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", name, err)
		}
	}

	tunnels, err := readSyncTunnels(dir)
	if err != nil {
		t.Fatalf("readSyncTunnels(dir): %v", err)
	}

	want := []syncTunnel{
		{Name: "a", Content: files["a.conf"]},
		{Name: "b", Content: files["b.conf"]},
	}
	if !reflect.DeepEqual(tunnels, want) {
		t.Fatalf("unexpected directory tunnels:\nwant: %#v\ngot:  %#v", want, tunnels)
	}
}

func TestFormatAndParseSyncPayloadJSON5(t *testing.T) {
	payload := syncPayload{
		Version:   1,
		UpdatedAt: "2026-08-24T11:22:33Z",
		Tunnels: []syncTunnel{
			{Name: "office", Content: "[Interface]\nPrivateKey = abc\n"},
			{Name: "lab", Content: "[Interface]\nAddress = 10.0.0.1/32\n"},
		},
	}

	content := formatSyncPayloadJSON5(payload)
	if !strings.Contains(content, "updatedAt: '2026-08-24T11:22:33Z'") {
		t.Fatalf("formatted content missing updatedAt: %s", content)
	}

	parsed, err := parseSyncPayload(content)
	if err != nil {
		t.Fatalf("parseSyncPayload: %v", err)
	}
	if !reflect.DeepEqual(parsed, payload) {
		t.Fatalf("unexpected parsed payload:\nwant: %#v\ngot:  %#v", payload, parsed)
	}
}

func TestSelectSyncFilePrefersNewestBackup(t *testing.T) {
	files := map[string]gistFile{
		"1.0.0(20260823-010203)[15Byte].json5": {Content: "old"},
		"1.0.0(20260824-020304)[15Byte].json5": {Content: "new"},
		"1.0.1.json5":                          {Content: "version"},
	}

	name, file, err := selectSyncFile(files, "")
	if err != nil {
		t.Fatalf("selectSyncFile: %v", err)
	}
	if got, want := name, "1.0.0(20260824-020304)[15Byte].json5"; got != want {
		t.Fatalf("expected file %q, got %q", want, got)
	}
	if got, want := file.Content, "new"; got != want {
		t.Fatalf("expected content %q, got %q", want, got)
	}
}

func TestWriteSyncPayloadToZip(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "download.zip")
	payload := syncPayload{
		Version:   1,
		UpdatedAt: "2026-08-24T11:22:33Z",
		Tunnels: []syncTunnel{
			{Name: "office", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x24) + "\n"},
			{Name: "lab", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x25) + "\n"},
		},
	}

	if err := writeSyncPayloadToPath(payload, outPath); err != nil {
		t.Fatalf("writeSyncPayloadToPath: %v", err)
	}

	reader, err := zip.OpenReader(outPath)
	if err != nil {
		t.Fatalf("OpenReader: %v", err)
	}
	defer reader.Close()

	got := map[string]string{}
	for _, file := range reader.File {
		rc, err := file.Open()
		if err != nil {
			t.Fatalf("Open(%q): %v", file.Name, err)
		}
		data, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			t.Fatalf("ReadAll(%q): %v", file.Name, err)
		}
		got[file.Name] = string(data)
	}

	want := map[string]string{
		"lab.conf":    payload.Tunnels[1].Content,
		"office.conf": payload.Tunnels[0].Content,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected zip payload:\nwant: %#v\ngot:  %#v", want, got)
	}
}

func TestGistSyncClientUploadUsesSharedSnapshotFormat(t *testing.T) {
	var gotMethod string
	var gotAuth string
	var gotPublic bool
	var gotDescription string
	var gotFileName string
	var gotPayload syncPayload

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotAuth = r.Header.Get("Authorization")

		var body gistRequest
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatalf("Decode(request): %v", err)
		}
		gotPublic = body.Public
		gotDescription = body.Description
		for name, file := range body.Files {
			gotFileName = name
			parsed, err := parseSyncPayload(file.Content)
			if err != nil {
				t.Fatalf("parseSyncPayload(request): %v", err)
			}
			gotPayload = parsed
		}

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gistResponse{
			ID: "gist-123",
			Files: map[string]gistFile{
				gotFileName: {Content: body.Files[gotFileName].Content},
			},
		})
	}))
	defer server.Close()

	client := newGistSyncClient(syncProvider{
		Name:    "github",
		APIBase: server.URL,
	}, server.Client())

	payload := syncPayload{
		Version:   1,
		UpdatedAt: time.Date(2026, 8, 24, 11, 22, 33, 0, time.UTC).Format(time.RFC3339),
		Tunnels: []syncTunnel{
			{Name: "office", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x26) + "\n"},
		},
	}

	result, err := client.Upload(syncSettings{Token: "token-123"}, payload, "wg|wireguard-go|windows|host")
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}

	if got, want := gotMethod, "POST"; got != want {
		t.Fatalf("expected method %q, got %q", want, got)
	}
	if got, want := gotAuth, "token token-123"; got != want {
		t.Fatalf("expected auth %q, got %q", want, got)
	}
	if gotPublic {
		t.Fatal("expected private gist request")
	}
	if got, want := gotDescription, "wg|wireguard-go|windows|host"; got != want {
		t.Fatalf("expected description %q, got %q", want, got)
	}
	if !isBackupFileName(gotFileName) {
		t.Fatalf("expected backup file name, got %q", gotFileName)
	}
	if !reflect.DeepEqual(gotPayload, payload) {
		t.Fatalf("unexpected uploaded payload:\nwant: %#v\ngot:  %#v", payload, gotPayload)
	}
	if got, want := result.GistID, "gist-123"; got != want {
		t.Fatalf("expected gist id %q, got %q", want, got)
	}
	if got, want := result.TunnelCount, 1; got != want {
		t.Fatalf("expected tunnel count %d, got %d", want, got)
	}
}

func TestLoadSyncConfigSupportsJSON5(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "sync.json5")
	content := strings.Join([]string{
		"{",
		"  // upload or download",
		"  provider: 'github',",
		"  action: 'upload',",
		"  token: 'ghp_example',",
		"  gistId: 'gist-123',",
		"  path: 'conf',",
		"  remoteFile: '1.0.0(20260824-112233)[256Byte].json5',",
		"}",
		"",
	}, "\n")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := loadSyncConfig(path)
	if err != nil {
		t.Fatalf("loadSyncConfig: %v", err)
	}

	want := syncConfigFile{
		Provider:   "github",
		Action:     "upload",
		Token:      "ghp_example",
		GistID:     "gist-123",
		Path:       "conf",
		RemoteFile: "1.0.0(20260824-112233)[256Byte].json5",
	}
	if !reflect.DeepEqual(cfg, want) {
		t.Fatalf("unexpected sync config:\nwant: %#v\ngot:  %#v", want, cfg)
	}
}

func TestApplySyncConfigOverridesOnlyMissingCLIValues(t *testing.T) {
	base := syncConfigFile{
		Provider:   "gitee",
		Action:     "download",
		Token:      "base-token",
		GistID:     "base-gist",
		Path:       "conf/base",
		RemoteFile: "base.json5",
	}

	merged := applySyncConfigOverrides(base, "github", "", "", "", "conf/override", "")
	want := syncConfigFile{
		Provider:   "github",
		Action:     "download",
		Token:      "base-token",
		GistID:     "base-gist",
		Path:       "conf/override",
		RemoteFile: "base.json5",
	}
	if !reflect.DeepEqual(merged, want) {
		t.Fatalf("unexpected merged config:\nwant: %#v\ngot:  %#v", want, merged)
	}
}

func TestExampleSyncConfigIsValid(t *testing.T) {
	cfg, err := loadSyncConfig("example.json5")
	if err != nil {
		t.Fatalf("loadSyncConfig(example.json5): %v", err)
	}
	if got, want := cfg.Provider, "github"; got != want {
		t.Fatalf("expected provider %q, got %q", want, got)
	}
	if got, want := cfg.Path, "conf"; got != want {
		t.Fatalf("expected path %q, got %q", want, got)
	}
}

func TestWriteSyncPayloadToDirectoryCreatesConfFiles(t *testing.T) {
	dir := t.TempDir()
	outPath := filepath.Join(dir, "downloaded")
	payload := syncPayload{
		Version:   1,
		UpdatedAt: "2026-08-25T02:44:00Z",
		Tunnels: []syncTunnel{
			{Name: "office", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x27) + "\n"},
			{Name: "lab", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x28) + "\n"},
		},
	}

	if err := writeSyncPayloadToPath(payload, outPath); err != nil {
		t.Fatalf("writeSyncPayloadToPath: %v", err)
	}
	for name, want := range map[string]string{
		"office.conf": payload.Tunnels[0].Content,
		"lab.conf":    payload.Tunnels[1].Content,
	} {
		data, err := os.ReadFile(filepath.Join(outPath, name))
		if err != nil {
			t.Fatalf("ReadFile(%q): %v", name, err)
		}
		if got := string(data); got != want {
			t.Fatalf("expected file %q content %q, got %q", name, want, got)
		}
	}
}

func TestRunSyncCommandDownloadLogsSelectedRemoteFileAndTunnelCount(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gistResponse{
			ID: "gist-123",
			Files: map[string]gistFile{
				"1.0.0(20260825-104400)[128Byte].json5": {
					Content: formatSyncPayloadJSON5(syncPayload{
						Version:   1,
						UpdatedAt: "2026-08-25T02:44:00Z",
						Tunnels: []syncTunnel{
							{Name: "office", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x29) + "\n"},
							{Name: "lab", Content: "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x2b) + "\n"},
						},
					}),
				},
			},
		})
	}))
	defer server.Close()

	client := newGistSyncClient(syncProvider{Name: "gitee", APIBase: server.URL}, server.Client())
	var output bytes.Buffer
	outPath := filepath.Join(t.TempDir(), "download")

	if err := runSyncCommandWithClient(&output, client, "gitee", "download", outPath, "token-123", "gist-123", ""); err != nil {
		t.Fatalf("runSyncCommandWithClient: %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"[sync] 提供方=gitee 操作=download",
		"[sync] 开始从远端读取 Gist: gist-123",
		"[sync] 已选择远端文件: 1.0.0(20260825-104400)[128Byte].json5",
		"[sync] 远端配置数量: 2",
		"[sync] 开始写入本地目录: " + outPath,
		"同步完成",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, got)
		}
	}
	for _, name := range []string{"office.conf", "lab.conf"} {
		if _, err := os.Stat(filepath.Join(outPath, name)); err != nil {
			t.Fatalf("expected downloaded file %q: %v", name, err)
		}
	}
}

func TestRunSyncCommandUploadLogsLocalTunnelCount(t *testing.T) {
	dir := t.TempDir()
	confDir := filepath.Join(dir, "conf")
	if err := os.MkdirAll(confDir, 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	for name, body := range map[string]string{
		"office.conf": "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x2a) + "\n",
		"lab.conf":    "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x2c) + "\n",
	} {
		if err := os.WriteFile(filepath.Join(confDir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("WriteFile(%q): %v", name, err)
		}
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(gistResponse{
			ID:      "gist-234",
			HTMLURL: "https://gitee.com/tea4go/codes/6yivgwt5pjceb0duhas7949",
			Files:   map[string]gistFile{},
		})
	}))
	defer server.Close()

	client := newGistSyncClient(syncProvider{Name: "github", APIBase: server.URL}, server.Client())
	var output bytes.Buffer

	if err := runSyncCommandWithClient(&output, client, "github", "upload", confDir, "token-456", "", ""); err != nil {
		t.Fatalf("runSyncCommandWithClient: %v", err)
	}

	got := output.String()
	for _, want := range []string{
		"[sync] 提供方=github 操作=upload",
		"[sync] 开始读取本地目录: " + confDir,
		"[sync] 本地配置数量: 2",
		"[sync] 开始上传到远端 Gist",
		"[sync] 上传完成，远端 Gist: gist-234",
		"[sync] 上传链接: https://gitee.com/tea4go/codes/6yivgwt5pjceb0duhas7949",
		"同步完成",
		"https://gitee.com/tea4go/codes/6yivgwt5pjceb0duhas7949",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected output to contain %q, got:\n%s", want, got)
		}
	}
}

func TestLoadSyncConfigAcceptsLegacyConfileAsPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "sync.json5")
	content := strings.Join([]string{
		"{",
		"  provider: 'gitee',",
		"  action: 'download',",
		"  confile: 'conf',",
		"}",
		"",
	}, "\n")
	if err := os.WriteFile(cfgPath, []byte(content), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := loadSyncConfig(cfgPath)
	if err != nil {
		t.Fatalf("loadSyncConfig: %v", err)
	}
	if got, want := cfg.Path, "conf"; got != want {
		t.Fatalf("expected path %q, got %q", want, got)
	}
}

func TestRunSyncCommandDownloadLogsHelpfulFailure(t *testing.T) {
	fakeClient := &gistSyncClient{provider: syncProvider{Name: "gitee"}}
	var output bytes.Buffer

	err := runSyncCommandWithClient(&output, fakeClient, "gitee", "download", "conf", "token", "gist-123", "")
	if !errors.Is(err, errSyncClientMissingDoer) {
		t.Fatalf("expected errSyncClientMissingDoer, got %v", err)
	}
	if got := output.String(); !strings.Contains(got, "[sync] 开始从远端读取 Gist: gist-123") {
		t.Fatalf("expected output to contain download start log, got:\n%s", got)
	}
}

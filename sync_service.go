package main

import (
	"archive/zip"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"
)

var errSyncClientMissingDoer = errors.New("SYNC_HTTP_CLIENT_MISSING")

type syncTunnel struct {
	Name    string `json:"name"`
	Content string `json:"content"`
}

type syncPayload struct {
	Version   int          `json:"version"`
	UpdatedAt string       `json:"updatedAt"`
	Tunnels   []syncTunnel `json:"tunnels"`
}

type syncSettings struct {
	Token  string
	GistID string
}

type syncConfigFile struct {
	Provider   string `json:"provider"`
	Action     string `json:"action"`
	Token      string `json:"token"`
	GistID     string `json:"gistId"`
	Path       string `json:"path"`
	Confile    string `json:"confile"`
	RemoteFile string `json:"remoteFile"`
}

type syncResult struct {
	GistID      string
	TunnelCount int
	FileName    string
}

type syncProvider struct {
	Name    string
	APIBase string
}

type gistFileRequest struct {
	Content string `json:"content"`
}

type gistRequest struct {
	Description string                     `json:"description,omitempty"`
	Public      bool                       `json:"public"`
	Files       map[string]gistFileRequest `json:"files"`
}

type gistFile struct {
	Content string `json:"content"`
	Size    int    `json:"size,omitempty"`
}

type gistResponse struct {
	ID          string              `json:"id"`
	Description string              `json:"description,omitempty"`
	Files       map[string]gistFile `json:"files"`
}

type gistSyncClient struct {
	provider   syncProvider
	httpClient *http.Client
}

func newGistSyncClient(provider syncProvider, httpClient *http.Client) *gistSyncClient {
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	return &gistSyncClient{
		provider:   provider,
		httpClient: httpClient,
	}
}

func (c *gistSyncClient) Upload(settings syncSettings, payload syncPayload, description string) (syncResult, error) {
	token := strings.TrimSpace(settings.Token)
	if token == "" {
		return syncResult{}, errors.New("TOKEN_REQUIRED")
	}
	if len(payload.Tunnels) == 0 {
		return syncResult{}, errors.New("NO_TUNNELS")
	}

	content := formatSyncPayloadJSON5(payload)
	fileName := buildBackupFileName(time.Now().UTC(), len([]byte(content)))
	body := gistRequest{
		Description: description,
		Public:      false,
		Files: map[string]gistFileRequest{
			fileName: {Content: content},
		},
	}

	method := http.MethodPost
	url := c.provider.APIBase
	if gistID := strings.TrimSpace(settings.GistID); gistID != "" {
		method = http.MethodPatch
		url = strings.TrimRight(c.provider.APIBase, "/") + "/" + gistID
	}

	var response gistResponse
	if err := c.doJSON(method, url, token, body, &response); err != nil {
		return syncResult{}, err
	}
	if strings.TrimSpace(response.ID) == "" {
		return syncResult{}, errors.New("INVALID_RESPONSE")
	}

	return syncResult{
		GistID:      response.ID,
		TunnelCount: len(payload.Tunnels),
		FileName:    fileName,
	}, nil
}

func (c *gistSyncClient) Download(settings syncSettings, preferredFile string) (syncPayload, string, error) {
	token := strings.TrimSpace(settings.Token)
	if token == "" {
		return syncPayload{}, "", errors.New("TOKEN_REQUIRED")
	}
	gistID := strings.TrimSpace(settings.GistID)
	if gistID == "" {
		return syncPayload{}, "", errors.New("GIST_ID_REQUIRED")
	}

	var response gistResponse
	if err := c.doJSON(http.MethodGet, strings.TrimRight(c.provider.APIBase, "/")+"/"+gistID, token, nil, &response); err != nil {
		return syncPayload{}, "", err
	}

	fileName, file, err := selectSyncFile(response.Files, preferredFile)
	if err != nil {
		return syncPayload{}, "", err
	}

	payload, err := parseSyncPayload(file.Content)
	if err != nil {
		return syncPayload{}, "", err
	}
	if err := validateSyncPayload(payload); err != nil {
		return syncPayload{}, "", err
	}

	return payload, fileName, nil
}

func (c *gistSyncClient) doJSON(method string, url string, token string, requestBody any, responseBody any) error {
	if c == nil || c.httpClient == nil {
		return errSyncClientMissingDoer
	}
	var bodyReader io.Reader
	if requestBody != nil {
		data, err := json.Marshal(requestBody)
		if err != nil {
			return err
		}
		bodyReader = bytes.NewReader(data)
	}

	request, err := http.NewRequest(method, url, bodyReader)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("Content-Type", "application/json;charset=UTF-8")
	request.Header.Set("User-Agent", "wireguard-go")
	request.Header.Set("Authorization", "token "+token)

	response, err := c.httpClient.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()

	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return fmt.Errorf("HTTP_%d", response.StatusCode)
	}
	if responseBody == nil {
		return nil
	}
	return json.NewDecoder(response.Body).Decode(responseBody)
}

func getSyncProvider(name string) (syncProvider, error) {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "github":
		return syncProvider{Name: "github", APIBase: "https://api.github.com/gists"}, nil
	case "gitee":
		return syncProvider{Name: "gitee", APIBase: "https://gitee.com/api/v5/gists"}, nil
	default:
		return syncProvider{}, fmt.Errorf("unsupported sync provider: %s", name)
	}
}

func buildSyncDescription() string {
	host, err := os.Hostname()
	if err != nil || strings.TrimSpace(host) == "" {
		host = "unknown-host"
	}
	host = sanitizeSyncName(host)
	return fmt.Sprintf("wg|wireguard-go|%s|%s", runtime.GOOS, host)
}

func loadSyncConfig(path string) (syncConfigFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return syncConfigFile{}, err
	}

	normalized, err := normalizeJSON5(string(data))
	if err != nil {
		return syncConfigFile{}, err
	}

	var cfg syncConfigFile
	if err := json.Unmarshal([]byte(normalized), &cfg); err != nil {
		return syncConfigFile{}, err
	}
	return normalizeSyncConfig(cfg), nil
}

func applySyncConfigOverrides(base syncConfigFile, provider string, action string, token string, gistID string, path string, remoteFile string) syncConfigFile {
	merged := normalizeSyncConfig(base)
	if value := strings.TrimSpace(provider); value != "" {
		merged.Provider = value
	}
	if value := strings.TrimSpace(action); value != "" {
		merged.Action = value
	}
	if value := strings.TrimSpace(token); value != "" {
		merged.Token = value
	}
	if value := strings.TrimSpace(gistID); value != "" {
		merged.GistID = value
	}
	if value := strings.TrimSpace(path); value != "" {
		merged.Path = value
	}
	if value := strings.TrimSpace(remoteFile); value != "" {
		merged.RemoteFile = value
	}
	return merged
}

func normalizeSyncConfig(cfg syncConfigFile) syncConfigFile {
	cfg.Provider = strings.TrimSpace(cfg.Provider)
	cfg.Action = strings.TrimSpace(cfg.Action)
	cfg.Token = strings.TrimSpace(cfg.Token)
	cfg.GistID = strings.TrimSpace(cfg.GistID)
	cfg.Path = strings.TrimSpace(cfg.Path)
	cfg.Confile = strings.TrimSpace(cfg.Confile)
	cfg.RemoteFile = strings.TrimSpace(cfg.RemoteFile)
	if cfg.Path == "" && cfg.Confile != "" {
		cfg.Path = cfg.Confile
	}
	cfg.Confile = ""
	return cfg
}

func runSyncCommand(stdout io.Writer, providerName string, action string, path string, token string, gistID string, remoteFile string) error {
	provider, err := getSyncProvider(providerName)
	if err != nil {
		return err
	}

	client := newGistSyncClient(provider, nil)
	return runSyncCommandWithClient(stdout, client, providerName, action, path, token, gistID, remoteFile)
}

func runSyncCommandWithClient(stdout io.Writer, client *gistSyncClient, providerName string, action string, path string, token string, gistID string, remoteFile string) error {
	logSync(stdout, "提供方=%s 操作=%s", providerName, action)

	if client == nil {
		provider, err := getSyncProvider(providerName)
		if err != nil {
			return err
		}
		client = newGistSyncClient(provider, nil)
	}

	settings := syncSettings{
		Token:  token,
		GistID: gistID,
	}

	switch strings.ToLower(strings.TrimSpace(action)) {
	case "upload":
		if strings.TrimSpace(path) == "" {
			return errors.New("SYNC_PATH_REQUIRED")
		}
		logSync(stdout, "开始读取本地目录: %s", path)
		tunnels, err := readSyncTunnels(path)
		if err != nil {
			return err
		}
		logSync(stdout, "本地配置数量: %d", len(tunnels))
		payload := syncPayload{
			Version:   1,
			UpdatedAt: time.Now().UTC().Format(time.RFC3339),
			Tunnels:   tunnels,
		}
		logSync(stdout, "开始上传到远端 Gist")
		result, err := client.Upload(settings, payload, buildSyncDescription())
		if err != nil {
			return err
		}
		logSync(stdout, "上传完成，远端 Gist: %s", result.GistID)
		return nil

	case "download":
		if strings.TrimSpace(path) == "" {
			return errors.New("SYNC_PATH_REQUIRED")
		}
		logSync(stdout, "开始从远端读取 Gist: %s", gistID)
		payload, fileName, err := client.Download(settings, remoteFile)
		if err != nil {
			return err
		}
		logSync(stdout, "已选择远端文件: %s", fileName)
		logSync(stdout, "远端配置数量: %d", len(payload.Tunnels))
		logSync(stdout, "开始写入本地目录: %s", path)
		if err := writeSyncPayloadToPath(payload, path); err != nil {
			return err
		}
		fmt.Printf("同步完成\n")
		return nil
	}

	return fmt.Errorf("unsupported sync action: %s", action)
}

func logSync(stdout io.Writer, format string, args ...any) {
	if stdout == nil {
		return
	}
	fmt.Fprintf(stdout, "[sync] "+format+"\n", args...)
}

func readSyncTunnels(path string) ([]syncTunnel, error) {
	if stat, err := os.Stat(path); err == nil && stat.IsDir() {
		entries, err := os.ReadDir(path)
		if err != nil {
			return nil, err
		}
		tunnels := make([]syncTunnel, 0, len(entries))
		for _, entry := range entries {
			if entry.IsDir() || !strings.EqualFold(filepath.Ext(entry.Name()), ".conf") {
				continue
			}
			data, err := os.ReadFile(filepath.Join(path, entry.Name()))
			if err != nil {
				return nil, err
			}
			tunnel := syncTunnel{
				Name:    interfaceNameFromPath(entry.Name()),
				Content: string(data),
			}
			if err := validateSyncTunnel(tunnel); err != nil {
				return nil, err
			}
			tunnels = append(tunnels, tunnel)
		}
		sort.Slice(tunnels, func(i, j int) bool {
			return strings.ToLower(tunnels[i].Name) < strings.ToLower(tunnels[j].Name)
		})
		if len(tunnels) == 0 {
			return nil, fmt.Errorf("目录中未找到 .conf 配置文件: %s", path)
		}
		return tunnels, nil
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".conf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		tunnel := syncTunnel{
			Name:    interfaceNameFromPath(path),
			Content: string(data),
		}
		if err := validateSyncTunnel(tunnel); err != nil {
			return nil, err
		}
		return []syncTunnel{tunnel}, nil

	case ".zip":
		reader, err := zip.OpenReader(path)
		if err != nil {
			return nil, err
		}
		defer reader.Close()

		entries := make([]*zip.File, 0, len(reader.File))
		for _, file := range reader.File {
			if file.FileInfo().IsDir() {
				continue
			}
			if strings.EqualFold(filepath.Ext(file.Name), ".conf") {
				entries = append(entries, file)
			}
		}
		sort.Slice(entries, func(i, j int) bool {
			leftName := strings.ToLower(interfaceNameFromPath(entries[i].Name))
			rightName := strings.ToLower(interfaceNameFromPath(entries[j].Name))
			if leftName != rightName {
				return leftName < rightName
			}
			return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
		})
		if len(entries) == 0 {
			return nil, errors.New("ZIP_NO_CONFIGS")
		}

		tunnels := make([]syncTunnel, 0, len(entries))
		for _, entry := range entries {
			rc, err := entry.Open()
			if err != nil {
				return nil, err
			}
			data, err := io.ReadAll(rc)
			closeErr := rc.Close()
			if err != nil {
				return nil, err
			}
			if closeErr != nil {
				return nil, closeErr
			}
			tunnel := syncTunnel{
				Name:    interfaceNameFromPath(entry.Name),
				Content: string(data),
			}
			if err := validateSyncTunnel(tunnel); err != nil {
				return nil, err
			}
			tunnels = append(tunnels, tunnel)
		}
		return tunnels, nil
	}

	return nil, fmt.Errorf("仅支持 .conf 或 .zip 配置文件: %s", path)
}

func validateSyncPayload(payload syncPayload) error {
	if payload.Version != 1 {
		return errors.New("INVALID_REMOTE_CONFIG")
	}
	if len(payload.Tunnels) == 0 {
		return errors.New("REMOTE_NO_CONFIGS")
	}
	for _, tunnel := range payload.Tunnels {
		if err := validateSyncTunnel(tunnel); err != nil {
			return err
		}
	}
	return nil
}

func validateSyncTunnel(tunnel syncTunnel) error {
	name := strings.TrimSpace(tunnel.Name)
	if name == "" || len(name) > 128 || strings.Contains(name, "/") || strings.Contains(name, "\\") {
		return errors.New("INVALID_REMOTE_CONFIG")
	}
	cfg, _ := parseTunnelConfig([]byte(tunnel.Content), name+".conf")
	if cfg == nil {
		return fmt.Errorf("INVALID_REMOTE_CONFIG:%s", name)
	}
	return nil
}

func writeSyncPayloadToPath(payload syncPayload, path string) error {
	if err := validateSyncPayload(payload); err != nil {
		return err
	}

	if filepath.Ext(path) == "" {
		if err := os.MkdirAll(path, 0o755); err != nil {
			return err
		}
		tunnels := append([]syncTunnel(nil), payload.Tunnels...)
		sort.Slice(tunnels, func(i, j int) bool {
			return strings.ToLower(tunnels[i].Name) < strings.ToLower(tunnels[j].Name)
		})
		for _, tunnel := range tunnels {
			if err := os.WriteFile(filepath.Join(path, tunnel.Name+".conf"), []byte(tunnel.Content), 0o644); err != nil {
				return err
			}
		}
		return nil
	}

	switch strings.ToLower(filepath.Ext(path)) {
	case ".conf":
		if len(payload.Tunnels) != 1 {
			return fmt.Errorf("远端包含 %d 个配置，输出到 .conf 不可行，请改用 .zip: %s", len(payload.Tunnels), path)
		}
		return os.WriteFile(path, []byte(payload.Tunnels[0].Content), 0o644)

	case ".zip":
		file, err := os.Create(path)
		if err != nil {
			return err
		}
		defer file.Close()

		writer := zip.NewWriter(file)
		tunnels := append([]syncTunnel(nil), payload.Tunnels...)
		sort.Slice(tunnels, func(i, j int) bool {
			return strings.ToLower(tunnels[i].Name) < strings.ToLower(tunnels[j].Name)
		})
		for _, tunnel := range tunnels {
			entry, err := writer.Create(tunnel.Name + ".conf")
			if err != nil {
				writer.Close()
				return err
			}
			if _, err := entry.Write([]byte(tunnel.Content)); err != nil {
				writer.Close()
				return err
			}
		}
		return writer.Close()
	}

	return fmt.Errorf("下载输出路径必须是目录、.conf 或 .zip: %s", path)
}

func buildBackupFileName(backupTime time.Time, fileSize int) string {
	version := strings.TrimPrefix(appVer, "v")
	for _, separator := range []string{"_B", "-B"} {
		if index := strings.Index(version, separator); index >= 0 {
			version = version[:index]
		}
	}
	if strings.TrimSpace(version) == "" {
		version = "0.0.1"
	}

	timestamp := backupTime.UTC().Format("20060102-150405")
	return fmt.Sprintf("%s(%s)[%dByte].json5", version, timestamp, fileSize)
}

func isBackupFileName(fileName string) bool {
	return matchSyncPattern(fileName, `^\d+\.\d+\.\d+\(\d{8}-\d{6}\)\[\d+Byte\]\.json5$`) ||
		matchSyncPattern(fileName, `^\d+\.\d+\.\d+\(\d{8}-\d{6}\)\.json5$`) ||
		matchSyncPattern(fileName, `^\d+\.\d+\.\d+\.json5$`) ||
		fileName == "wireguard-harmony.json5" ||
		fileName == "wireguard-harmony.json"
}

func matchSyncPattern(value string, pattern string) bool {
	matched, _ := filepath.Match(pattern, value)
	if matched {
		return true
	}
	// filepath.Match is not regex-based, so keep a narrow fallback for the
	// sync file names that contain fixed separators.
	switch pattern {
	case `^\d+\.\d+\.\d+\(\d{8}-\d{6}\)\[\d+Byte\]\.json5$`:
		return syncPatternMatch(value, true, true)
	case `^\d+\.\d+\.\d+\(\d{8}-\d{6}\)\.json5$`:
		return syncPatternMatch(value, true, false)
	case `^\d+\.\d+\.\d+\.json5$`:
		return syncVersionFileMatch(value)
	default:
		return false
	}
}

func syncPatternMatch(value string, requireTimestamp bool, requireSize bool) bool {
	if !strings.HasSuffix(value, ".json5") {
		return false
	}
	base := strings.TrimSuffix(value, ".json5")
	open := strings.LastIndex(base, "(")
	close := strings.LastIndex(base, ")")
	if open <= 0 || close <= open || (requireTimestamp && close-open-1 != len("20260824-112233")) {
		return false
	}
	if !syncVersionFileMatch(base[:open] + ".json5") {
		return false
	}
	timestamp := base[open+1 : close]
	if _, err := time.Parse("20060102-150405", timestamp); err != nil {
		return false
	}
	if !requireSize {
		return close == len(base)-1
	}
	sizePart := base[close+1:]
	if !strings.HasPrefix(sizePart, "[") || !strings.HasSuffix(sizePart, "Byte]") {
		return false
	}
	_, err := strconv.Atoi(strings.TrimSuffix(strings.TrimPrefix(sizePart, "["), "Byte]"))
	return err == nil
}

func syncVersionFileMatch(value string) bool {
	if !strings.HasSuffix(value, ".json5") {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(value, ".json5"), ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if part == "" {
			return false
		}
		if _, err := strconv.Atoi(part); err != nil {
			return false
		}
	}
	return true
}

func selectSyncFile(files map[string]gistFile, preferredFile string) (string, gistFile, error) {
	if len(files) == 0 {
		return "", gistFile{}, errors.New("REMOTE_NO_CONFIGS")
	}

	if preferredFile = strings.TrimSpace(preferredFile); preferredFile != "" {
		file, ok := files[preferredFile]
		if !ok || strings.TrimSpace(file.Content) == "" {
			return "", gistFile{}, errors.New("REMOTE_FILE_NOT_FOUND")
		}
		return preferredFile, file, nil
	}

	candidates := make([]string, 0, len(files))
	for name, file := range files {
		if strings.TrimSpace(file.Content) == "" {
			continue
		}
		if isBackupFileName(name) {
			candidates = append(candidates, name)
		}
	}
	if len(candidates) == 0 {
		return "", gistFile{}, errors.New("REMOTE_NO_CONFIGS")
	}

	sort.Slice(candidates, func(i, j int) bool {
		left := candidates[i]
		right := candidates[j]
		leftTS := getBackupTimestamp(left)
		rightTS := getBackupTimestamp(right)
		if leftTS != "" || rightTS != "" {
			return rightTS < leftTS
		}
		return compareVersionFileNames(left, right) > 0
	})

	selected := candidates[0]
	return selected, files[selected], nil
}

func getBackupTimestamp(fileName string) string {
	open := strings.LastIndex(fileName, "(")
	close := strings.LastIndex(fileName, ")")
	if open < 0 || close <= open {
		return ""
	}
	return fileName[open+1 : close]
}

func compareVersionFileNames(left string, right string) int {
	leftParts := strings.Split(strings.TrimSuffix(left, ".json5"), ".")
	rightParts := strings.Split(strings.TrimSuffix(right, ".json5"), ".")
	for index := 0; index < 3; index++ {
		leftValue, _ := strconv.Atoi(leftParts[index])
		rightValue, _ := strconv.Atoi(rightParts[index])
		if leftValue != rightValue {
			return leftValue - rightValue
		}
	}
	return 0
}

func formatSyncPayloadJSON5(payload syncPayload) string {
	lines := []string{
		"{",
		"    version: 1,",
		"    updatedAt: " + formatJSON5String(payload.UpdatedAt) + ",",
		"    tunnels: [",
	}
	for index, tunnel := range payload.Tunnels {
		lines = append(lines, "        {")
		lines = append(lines, "            name: "+formatJSON5String(tunnel.Name)+",")
		lines = append(lines, "            content: "+formatJSON5MultilineString(tunnel.Content))
		if index == len(payload.Tunnels)-1 {
			lines = append(lines, "        }")
		} else {
			lines = append(lines, "        },")
		}
	}
	lines = append(lines, "    ]", "}")
	return strings.Join(lines, "\n") + "\n"
}

func formatJSON5String(value string) string {
	return "'" + escapeJSON5Line(value) + "'"
}

func formatJSON5MultilineString(value string) string {
	normalized := strings.ReplaceAll(strings.ReplaceAll(value, "\r\n", "\n"), "\r", "\n")
	parts := strings.Split(normalized, "\n")
	return "'" + strings.Join(mapSyncStrings(parts, escapeJSON5Line), "\\n\\\n") + "'"
}

func mapSyncStrings(values []string, fn func(string) string) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = fn(value)
	}
	return result
}

func escapeJSON5Line(value string) string {
	replacer := strings.NewReplacer(
		"\\", "\\\\",
		"'", "\\'",
		"\t", "\\t",
		"\b", "\\b",
		"\f", "\\f",
		"\v", "\\v",
		"\u2028", "\\u2028",
		"\u2029", "\\u2029",
	)
	return replacer.Replace(value)
}

func parseSyncPayload(content string) (syncPayload, error) {
	var payload syncPayload
	if err := json.Unmarshal([]byte(content), &payload); err == nil {
		return payload, nil
	}

	normalized, err := normalizeJSON5(content)
	if err != nil {
		return syncPayload{}, err
	}
	if err := json.Unmarshal([]byte(normalized), &payload); err != nil {
		return syncPayload{}, err
	}
	return payload, nil
}

func normalizeJSON5(source string) (string, error) {
	var result strings.Builder
	for index := 0; index < len(source); {
		current := source[index]
		if current == '"' || current == '\'' {
			value, nextIndex, err := readJSON5String(source, index)
			if err != nil {
				return "", err
			}
			encoded, err := json.Marshal(value)
			if err != nil {
				return "", err
			}
			result.Write(encoded)
			index = nextIndex
			continue
		}
		if current == '/' && index+1 < len(source) && source[index+1] == '/' {
			index += 2
			for index < len(source) && source[index] != '\n' && source[index] != '\r' {
				index++
			}
			continue
		}
		if current == '/' && index+1 < len(source) && source[index+1] == '*' {
			index += 2
			for index+1 < len(source) && !(source[index] == '*' && source[index+1] == '/') {
				index++
			}
			index += 2
			continue
		}
		if current == ',' {
			next := skipJSON5Whitespace(source, index+1)
			if next < len(source) && (source[next] == '}' || source[next] == ']') {
				index++
				continue
			}
		}
		if isJSON5IdentifierStart(current) {
			end := index + 1
			for end < len(source) && isJSON5IdentifierPart(source[end]) {
				end++
			}
			next := skipJSON5Whitespace(source, end)
			if next < len(source) && source[next] == ':' {
				encoded, err := json.Marshal(source[index:end])
				if err != nil {
					return "", err
				}
				result.Write(encoded)
				index = end
				continue
			}
		}
		result.WriteByte(current)
		index++
	}
	return result.String(), nil
}

func readJSON5String(source string, startIndex int) (string, int, error) {
	quote := source[startIndex]
	var result strings.Builder
	for index := startIndex + 1; index < len(source); {
		current := source[index]
		if current == quote {
			return result.String(), index + 1, nil
		}
		if current != '\\' {
			result.WriteByte(current)
			index++
			continue
		}
		index++
		if index >= len(source) {
			break
		}
		escaped := source[index]
		switch escaped {
		case '\n':
			index++
			continue
		case '\r':
			index++
			if index < len(source) && source[index] == '\n' {
				index++
			}
			continue
		case 'n':
			result.WriteByte('\n')
		case 'r':
			result.WriteByte('\r')
		case 't':
			result.WriteByte('\t')
		case 'b':
			result.WriteByte('\b')
		case 'f':
			result.WriteByte('\f')
		case 'v':
			result.WriteByte('\v')
		case '0':
			result.WriteByte(0)
		case 'x':
			if index+2 >= len(source) {
				return "", 0, errors.New("INVALID_REMOTE_CONFIG")
			}
			value, err := strconv.ParseUint(source[index+1:index+3], 16, 8)
			if err != nil {
				return "", 0, err
			}
			result.WriteByte(byte(value))
			index += 2
		case 'u':
			if index+4 >= len(source) {
				return "", 0, errors.New("INVALID_REMOTE_CONFIG")
			}
			value, err := strconv.ParseUint(source[index+1:index+5], 16, 16)
			if err != nil {
				return "", 0, err
			}
			result.WriteRune(rune(value))
			index += 4
		default:
			result.WriteByte(escaped)
		}
		index++
	}
	return "", 0, errors.New("INVALID_REMOTE_CONFIG")
}

func skipJSON5Whitespace(source string, start int) int {
	index := start
	for index < len(source) {
		if strings.ContainsRune(" \t\r\n", rune(source[index])) {
			index++
			continue
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '/' {
			index += 2
			for index < len(source) && source[index] != '\n' && source[index] != '\r' {
				index++
			}
			continue
		}
		if index+1 < len(source) && source[index] == '/' && source[index+1] == '*' {
			index += 2
			for index+1 < len(source) && !(source[index] == '*' && source[index+1] == '/') {
				index++
			}
			index += 2
			continue
		}
		break
	}
	return index
}

func isJSON5IdentifierStart(value byte) bool {
	return value == '_' || value == '$' ||
		(value >= 'a' && value <= 'z') ||
		(value >= 'A' && value <= 'Z')
}

func isJSON5IdentifierPart(value byte) bool {
	return isJSON5IdentifierStart(value) || (value >= '0' && value <= '9')
}

func sanitizeSyncName(value string) string {
	sanitized := strings.TrimSpace(value)
	replacer := strings.NewReplacer("\\", "-", "/", "-", ":", "-", "*", "-", "?", "-", "\"", "-", "<", "-", ">", "-", "|", "-")
	sanitized = replacer.Replace(sanitized)
	sanitized = strings.ReplaceAll(sanitized, " ", "-")
	sanitized = strings.Trim(sanitized, ".-")
	if sanitized == "" {
		return "unknown"
	}
	if len(sanitized) > 64 {
		return sanitized[:64]
	}
	return sanitized
}

package main

import (
	"archive/zip"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type tunnelConfig struct {
	Source        string
	InterfaceName string
	UAPI          string
	MTU           int
	ListenPort    string
	Peers         []peerConfig
	IgnoredFields []string
}

type interfaceConfig struct {
	privateKey string
	listenPort string
	fwmark     string
	mtu        int
}

type peerConfig struct {
	publicKey                  string
	presharedKey               string
	allowedIPs                 []string
	endpoint                   string
	persistentKeepalive        string
	hasPersistentKeepaliveLine bool
}

func loadTunnelConfigs(path string) ([]*tunnelConfig, error) {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".conf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("读取配置文件失败: %w", err)
		}
		cfg, err := parseTunnelConfig(data, path)
		if err != nil {
			return nil, err
		}
		return []*tunnelConfig{cfg}, nil

	case ".zip":
		reader, err := zip.OpenReader(path)
		if err != nil {
			return nil, fmt.Errorf("打开配置压缩包失败: %w", err)
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
		if len(entries) == 0 {
			return nil, fmt.Errorf("压缩包中未找到 .conf 配置文件")
		}
		sort.Slice(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
		})

		configs := make([]*tunnelConfig, 0, len(entries))
		for _, entry := range entries {
			rc, err := entry.Open()
			if err != nil {
				return nil, fmt.Errorf("打开压缩包内配置文件失败: %w", err)
			}

			data, readErr := io.ReadAll(rc)
			closeErr := rc.Close()
			if readErr != nil {
				return nil, fmt.Errorf("读取压缩包内配置文件失败: %w", readErr)
			}
			if closeErr != nil {
				return nil, fmt.Errorf("关闭压缩包内配置文件失败: %w", closeErr)
			}

			cfg, err := parseTunnelConfig(data, fmt.Sprintf("%s (%s)", path, entry.Name))
			if err != nil {
				return nil, err
			}
			cfg.InterfaceName = interfaceNameFromPath(entry.Name)
			configs = append(configs, cfg)
		}
		return configs, nil

	default:
		return nil, fmt.Errorf("仅支持 .conf 或 .zip 配置文件: %s", path)
	}
}

func parseTunnelConfig(data []byte, source string) (*tunnelConfig, error) {
	var iface interfaceConfig
	var peers []peerConfig
	var currentPeer *peerConfig
	ignored := make(map[string]struct{})
	section := ""

	lines := strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n")
	for i, rawLine := range lines {
		line := trimConfigLine(rawLine)
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			switch section {
			case "interface":
				currentPeer = nil
			case "peer":
				peers = append(peers, peerConfig{})
				currentPeer = &peers[len(peers)-1]
			default:
				return nil, fmt.Errorf("%s:%d: 不支持的配置段 %q", source, i+1, line)
			}
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			return nil, fmt.Errorf("%s:%d: 配置行缺少 '=': %q", source, i+1, rawLine)
		}
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if err := parseInterfaceLine(&iface, ignored, key, value, source, i+1); err != nil {
				return nil, err
			}

		case "peer":
			if currentPeer == nil {
				return nil, fmt.Errorf("%s:%d: [Peer] 配置状态异常", source, i+1)
			}
			if err := parsePeerLine(currentPeer, ignored, key, value, source, i+1); err != nil {
				return nil, err
			}

		default:
			return nil, fmt.Errorf("%s:%d: 配置项出现在段外: %q", source, i+1, rawLine)
		}
	}

	uapi, err := buildUAPIConfig(iface, peers, source)
	if err != nil {
		return nil, err
	}

	ignoredFields := make([]string, 0, len(ignored))
	for field := range ignored {
		ignoredFields = append(ignoredFields, field)
	}
	sort.Strings(ignoredFields)

	return &tunnelConfig{
		Source:        source,
		InterfaceName: interfaceNameFromPath(source),
		UAPI:          uapi,
		MTU:           iface.mtu,
		ListenPort:    iface.listenPort,
		Peers:         append([]peerConfig(nil), peers...),
		IgnoredFields: ignoredFields,
	}, nil
}

func interfaceNameFromPath(path string) string {
	base := filepath.Base(path)
	ext := filepath.Ext(base)
	return strings.TrimSuffix(base, ext)
}

func describeTunnelConfig(cfg *tunnelConfig) string {
	allowedIPCount := 0
	for _, peer := range cfg.Peers {
		allowedIPCount += len(peer.allowedIPs)
	}

	parts := []string{
		"接口=" + cfg.InterfaceName,
		"来源=" + cfg.Source,
		fmt.Sprintf("Peer数=%d", len(cfg.Peers)),
		fmt.Sprintf("AllowedIPs数=%d", allowedIPCount),
	}
	if cfg.MTU > 0 {
		parts = append(parts, fmt.Sprintf("MTU=%d", cfg.MTU))
	}
	if cfg.ListenPort != "" {
		parts = append(parts, "ListenPort="+cfg.ListenPort)
	}
	if len(cfg.IgnoredFields) > 0 {
		parts = append(parts, "忽略字段="+strings.Join(cfg.IgnoredFields, ","))
	}
	return strings.Join(parts, " | ")
}

func describePeerConfig(peer peerConfig) string {
	parts := []string{
		"公钥=" + abbreviateHexKey(peer.publicKey),
		"AllowedIPs=" + strings.Join(peer.allowedIPs, ","),
	}
	if peer.endpoint != "" {
		parts = append(parts, "Endpoint="+peer.endpoint)
	}
	if peer.hasPersistentKeepaliveLine {
		parts = append(parts, "PersistentKeepalive="+peer.persistentKeepalive)
	}
	return strings.Join(parts, " | ")
}

func abbreviateHexKey(key string) string {
	if len(key) <= 12 {
		return key
	}
	return key[:6] + "..." + key[len(key)-6:]
}

func parseInterfaceLine(iface *interfaceConfig, ignored map[string]struct{}, key, value, source string, lineNo int) error {
	switch strings.ToLower(key) {
	case "privatekey":
		decoded, err := decodeBase64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Interface.PrivateKey 失败: %w", source, lineNo, err)
		}
		iface.privateKey = decoded

	case "listenport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Interface.ListenPort 失败: %w", source, lineNo, err)
		}
		iface.listenPort = strconv.FormatUint(port, 10)

	case "fwmark":
		mark, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Interface.FwMark 失败: %w", source, lineNo, err)
		}
		iface.fwmark = strconv.FormatUint(mark, 10)

	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu <= 0 {
			return fmt.Errorf("%s:%d: 解析 Interface.MTU 失败: %q", source, lineNo, value)
		}
		iface.mtu = mtu

	case "address", "dns", "table", "preup", "postup", "predown", "postdown", "saveconfig":
		ignored["Interface."+canonicalConfigKey(key)] = struct{}{}

	default:
		ignored["Interface."+canonicalConfigKey(key)] = struct{}{}
	}
	return nil
}

func parsePeerLine(peer *peerConfig, ignored map[string]struct{}, key, value, source string, lineNo int) error {
	switch strings.ToLower(key) {
	case "publickey":
		decoded, err := decodeBase64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PublicKey 失败: %w", source, lineNo, err)
		}
		peer.publicKey = decoded

	case "presharedkey":
		decoded, err := decodeBase64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PresharedKey 失败: %w", source, lineNo, err)
		}
		peer.presharedKey = decoded

	case "allowedips":
		parts := strings.Split(value, ",")
		peer.allowedIPs = peer.allowedIPs[:0]
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := netip.ParsePrefix(part); err != nil {
				return fmt.Errorf("%s:%d: 解析 Peer.AllowedIPs 失败: %w", source, lineNo, err)
			}
			peer.allowedIPs = append(peer.allowedIPs, part)
		}
		if len(peer.allowedIPs) == 0 {
			return fmt.Errorf("%s:%d: Peer.AllowedIPs 不能为空", source, lineNo)
		}

	case "endpoint":
		if value == "" {
			return fmt.Errorf("%s:%d: Peer.Endpoint 不能为空", source, lineNo)
		}
		peer.endpoint = value

	case "persistentkeepalive", "persistentkeepaliveinterval":
		peer.hasPersistentKeepaliveLine = true
		if strings.EqualFold(value, "off") {
			peer.persistentKeepalive = "0"
			return nil
		}
		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PersistentKeepalive 失败: %w", source, lineNo, err)
		}
		peer.persistentKeepalive = strconv.FormatUint(secs, 10)

	default:
		ignored["Peer."+canonicalConfigKey(key)] = struct{}{}
	}
	return nil
}

func buildUAPIConfig(iface interfaceConfig, peers []peerConfig, source string) (string, error) {
	lines := make([]string, 0, 4+len(peers)*8)

	if iface.privateKey != "" {
		lines = append(lines, "private_key="+iface.privateKey)
	}
	if iface.listenPort != "" {
		lines = append(lines, "listen_port="+iface.listenPort)
	}
	if iface.fwmark != "" {
		lines = append(lines, "fwmark="+iface.fwmark)
	}

	lines = append(lines, "replace_peers=true")
	for i, peer := range peers {
		if peer.publicKey == "" {
			return "", fmt.Errorf("%s: 第 %d 个 Peer 缺少 PublicKey", source, i+1)
		}
		lines = append(lines, "public_key="+peer.publicKey)
		if peer.presharedKey != "" {
			lines = append(lines, "preshared_key="+peer.presharedKey)
		}
		lines = append(lines, "protocol_version=1")
		lines = append(lines, "replace_allowed_ips=true")
		for _, allowedIP := range peer.allowedIPs {
			lines = append(lines, "allowed_ip="+allowedIP)
		}
		if peer.endpoint != "" {
			lines = append(lines, "endpoint="+peer.endpoint)
		}
		if peer.hasPersistentKeepaliveLine {
			lines = append(lines, "persistent_keepalive_interval="+peer.persistentKeepalive)
		}
	}

	return strings.Join(lines, "\n") + "\n", nil
}

func decodeBase64KeyToHex(value string) (string, error) {
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		return "", err
	}
	if len(decoded) != 32 {
		return "", fmt.Errorf("密钥长度必须为 32 字节，实际为 %d", len(decoded))
	}
	return hex.EncodeToString(decoded), nil
}

func trimConfigLine(line string) string {
	line = strings.TrimSpace(line)
	if line == "" {
		return ""
	}
	if idx := strings.IndexAny(line, "#;"); idx >= 0 {
		line = strings.TrimSpace(line[:idx])
	}
	return line
}

func canonicalConfigKey(key string) string {
	switch strings.ToLower(strings.TrimSpace(key)) {
	case "privatekey":
		return "PrivateKey"
	case "listenport":
		return "ListenPort"
	case "fwmark":
		return "FwMark"
	case "mtu":
		return "MTU"
	case "address":
		return "Address"
	case "dns":
		return "DNS"
	case "table":
		return "Table"
	case "preup":
		return "PreUp"
	case "postup":
		return "PostUp"
	case "predown":
		return "PreDown"
	case "postdown":
		return "PostDown"
	case "saveconfig":
		return "SaveConfig"
	case "publickey":
		return "PublicKey"
	case "presharedkey":
		return "PresharedKey"
	case "allowedips":
		return "AllowedIPs"
	case "endpoint":
		return "Endpoint"
	case "persistentkeepalive", "persistentkeepaliveinterval":
		return "PersistentKeepalive"
	default:
		return strings.TrimSpace(key)
	}
}

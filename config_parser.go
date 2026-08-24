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
	Addresses     []string
	Peers         []peerConfig
	IgnoredFields []string
}

type interfaceConfig struct {
	privateKey string
	listenPort string
	fwmark     string
	mtu        int
	addresses  []string
}

type peerConfig struct {
	name                       string
	publicKey                  string
	presharedKey               string
	allowedIPs                 []string
	endpoint                   string
	persistentKeepalive        string
	hasPersistentKeepaliveLine bool
}

func loadTunnelConfigs(path string) ([]*tunnelConfig, []string) {
	var warnings []string

	switch strings.ToLower(filepath.Ext(path)) {
	case ".conf":
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, []string{fmt.Sprintf("%s: 读取配置文件失败: %v", path, err)}
		}
		cfg, cfgWarnings := parseTunnelConfig(data, path)
		warnings = append(warnings, cfgWarnings...)
		if cfg == nil {
			return nil, warnings
		}
		return []*tunnelConfig{cfg}, warnings

	case ".zip":
		reader, err := zip.OpenReader(path)
		if err != nil {
			return nil, []string{fmt.Sprintf("%s: 打开配置压缩包失败: %v", path, err)}
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
			return nil, []string{fmt.Sprintf("%s: 压缩包中未找到 .conf 配置文件", path)}
		}

		sort.Slice(entries, func(i, j int) bool {
			return strings.ToLower(entries[i].Name) < strings.ToLower(entries[j].Name)
		})

		configs := make([]*tunnelConfig, 0, len(entries))
		for _, entry := range entries {
			rc, err := entry.Open()
			if err != nil {
				warnings = append(warnings, fmt.Sprintf("%s (%s): 打开压缩包内配置文件失败: %v", path, entry.Name, err))
				continue
			}

			data, readErr := io.ReadAll(rc)
			closeErr := rc.Close()
			if readErr != nil {
				warnings = append(warnings, fmt.Sprintf("%s (%s): 读取压缩包内配置文件失败: %v", path, entry.Name, readErr))
				continue
			}
			if closeErr != nil {
				warnings = append(warnings, fmt.Sprintf("%s (%s): 关闭压缩包内配置文件失败: %v", path, entry.Name, closeErr))
				continue
			}

			cfg, cfgWarnings := parseTunnelConfig(data, fmt.Sprintf("%s (%s)", path, entry.Name))
			warnings = append(warnings, cfgWarnings...)
			if cfg == nil {
				continue
			}
			cfg.InterfaceName = interfaceNameFromPath(entry.Name)
			configs = append(configs, cfg)
		}
		return configs, warnings

	default:
		return nil, []string{fmt.Sprintf("仅支持 .conf 或 .zip 配置文件: %s", path)}
	}
}

func parseTunnelConfig(data []byte, source string) (*tunnelConfig, []string) {
	var iface interfaceConfig
	var peers []peerConfig
	var currentPeer *peerConfig
	ignored := make(map[string]struct{})
	var warnings []string
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
				warnings = append(warnings, fmt.Sprintf("%s:%d: 不支持的配置段 %q，已忽略", source, i+1, line))
				section = "#ignored"
			}
			continue
		}

		if section == "#ignored" {
			continue
		}

		key, value, ok := strings.Cut(line, "=")
		if !ok {
			warnings = append(warnings, fmt.Sprintf("%s:%d: 配置行缺少 '='，已忽略: %q", source, i+1, rawLine))
			continue
		}

		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)

		switch section {
		case "interface":
			if err := parseInterfaceLine(&iface, ignored, key, value, source, i+1); err != nil {
				warnings = append(warnings, err.Error())
			}

		case "peer":
			if currentPeer == nil {
				warnings = append(warnings, fmt.Sprintf("%s:%d: [Peer] 配置状态异常，已忽略", source, i+1))
				continue
			}
			if err := parsePeerLine(currentPeer, ignored, key, value, source, i+1); err != nil {
				warnings = append(warnings, err.Error())
			}

		default:
			warnings = append(warnings, fmt.Sprintf("%s:%d: 配置项出现在段外，已忽略: %q", source, i+1, rawLine))
		}
	}

	uapi, usablePeers, buildWarnings := buildUAPIConfig(iface, peers, source)
	warnings = append(warnings, buildWarnings...)

	ignoredFields := make([]string, 0, len(ignored))
	for field := range ignored {
		ignoredFields = append(ignoredFields, field)
	}
	sort.Strings(ignoredFields)

	if iface.privateKey == "" && iface.listenPort == "" && iface.fwmark == "" && iface.mtu == 0 && len(iface.addresses) == 0 && len(usablePeers) == 0 {
		warnings = append(warnings, fmt.Sprintf("%s: 未提取到可用配置，已跳过", source))
		return nil, warnings
	}

	return &tunnelConfig{
		Source:        source,
		InterfaceName: interfaceNameFromPath(source),
		UAPI:          uapi,
		MTU:           iface.mtu,
		ListenPort:    iface.listenPort,
		Addresses:     append([]string(nil), iface.addresses...),
		Peers:         append([]peerConfig(nil), usablePeers...),
		IgnoredFields: ignoredFields,
	}, warnings
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
		fmt.Sprintf("节点数=%d", len(cfg.Peers)),
		fmt.Sprintf("允许IP数=%d", allowedIPCount),
	}
	if cfg.MTU > 0 {
		parts = append(parts, fmt.Sprintf("MTU=%d", cfg.MTU))
	}
	if cfg.ListenPort != "" {
		parts = append(parts, "监听="+cfg.ListenPort)
	}
	if len(cfg.Addresses) > 0 {
		parts = append(parts, "地址="+strings.Join(cfg.Addresses, ","))
	}
	if len(cfg.IgnoredFields) > 0 {
		parts = append(parts, "忽略字段="+strings.Join(cfg.IgnoredFields, ","))
	}
	return strings.Join(parts, ",")
}

func describePeerConfig(peer peerConfig) string {
	parts := make([]string, 0, 5)
	if peer.name != "" {
		parts = append(parts, "名称="+peer.name)
	}
	parts = append(parts,
		"公钥="+abbreviateHexKey(peer.publicKey),
		"允许IP="+strings.Join(peer.allowedIPs, ","),
	)
	if peer.endpoint != "" {
		parts = append(parts, "对端="+peer.endpoint)
	}
	if peer.hasPersistentKeepaliveLine {
		parts = append(parts, "保持="+peer.persistentKeepalive)
	}
	return strings.Join(parts, ",")
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
			return fmt.Errorf("%s:%d: 解析 Interface.PrivateKey 失败, %w", source, lineNo, err)
		}
		iface.privateKey = decoded

	case "listenport":
		port, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Interface.ListenPort 失败, %w", source, lineNo, err)
		}
		iface.listenPort = strconv.FormatUint(port, 10)

	case "fwmark":
		mark, err := strconv.ParseUint(value, 0, 32)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Interface.FwMark 失败, %w", source, lineNo, err)
		}
		iface.fwmark = strconv.FormatUint(mark, 10)

	case "mtu":
		mtu, err := strconv.Atoi(value)
		if err != nil || mtu <= 0 {
			return fmt.Errorf("%s:%d: 解析 Interface.MTU 失败: %q", source, lineNo, value)
		}
		iface.mtu = mtu

	case "address":
		parts := strings.Split(value, ",")
		parsed := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			prefix, err := netip.ParsePrefix(part)
			if err != nil {
				return fmt.Errorf("%s:%d: 解析 Interface.Address 失败, %w", source, lineNo, err)
			}
			parsed = append(parsed, prefix.String())
		}
		if len(parsed) == 0 {
			return fmt.Errorf("%s:%d: Interface.Address 不能为空", source, lineNo)
		}
		iface.addresses = append(iface.addresses, parsed...)

	case "dns", "table", "preup", "postup", "predown", "postdown", "saveconfig":
		ignored["Interface."+canonicalConfigKey(key)] = struct{}{}

	default:
		ignored["Interface."+canonicalConfigKey(key)] = struct{}{}
	}
	return nil
}

func parsePeerLine(peer *peerConfig, ignored map[string]struct{}, key, value, source string, lineNo int) error {
	switch strings.ToLower(key) {
	case "name":
		if value == "" {
			return fmt.Errorf("%s:%d: Peer.Name 不能为空", source, lineNo)
		}
		peer.name = value

	case "publickey":
		decoded, err := decodeBase64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PublicKey 失败, %w", source, lineNo, err)
		}
		peer.publicKey = decoded

	case "presharedkey":
		decoded, err := decodeBase64KeyToHex(value)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PresharedKey 失败, %w", source, lineNo, err)
		}
		peer.presharedKey = decoded

	case "allowedips":
		parts := strings.Split(value, ",")
		parsed := make([]string, 0, len(parts))
		for _, part := range parts {
			part = strings.TrimSpace(part)
			if part == "" {
				continue
			}
			if _, err := netip.ParsePrefix(part); err != nil {
				return fmt.Errorf("%s:%d: 解析 Peer.AllowedIPs 失败, %w", source, lineNo, err)
			}
			parsed = append(parsed, part)
		}
		if len(parsed) == 0 {
			return fmt.Errorf("%s:%d: Peer.AllowedIPs 不能为空", source, lineNo)
		}
		peer.allowedIPs = parsed

	case "endpoint":
		if value == "" {
			return fmt.Errorf("%s:%d: Peer.Endpoint 不能为空", source, lineNo)
		}
		peer.endpoint = value

	case "persistentkeepalive", "persistentkeepaliveinterval":
		if strings.EqualFold(value, "off") {
			peer.hasPersistentKeepaliveLine = true
			peer.persistentKeepalive = "0"
			return nil
		}
		secs, err := strconv.ParseUint(value, 10, 16)
		if err != nil {
			return fmt.Errorf("%s:%d: 解析 Peer.PersistentKeepalive 失败, %w", source, lineNo, err)
		}
		peer.hasPersistentKeepaliveLine = true
		peer.persistentKeepalive = strconv.FormatUint(secs, 10)

	default:
		ignored["Peer."+canonicalConfigKey(key)] = struct{}{}
	}
	return nil
}

func buildUAPIConfig(iface interfaceConfig, peers []peerConfig, source string) (string, []peerConfig, []string) {
	lines := make([]string, 0, 4+len(peers)*8)
	validPeers := make([]peerConfig, 0, len(peers))
	var warnings []string

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
			warnings = append(warnings, fmt.Sprintf("%s: 第 %d 个 Peer 缺少有效 PublicKey，已跳过", source, i+1))
			continue
		}
		lines = append(lines, "public_key="+peer.publicKey)
		if peer.name != "" {
			lines = append(lines, "name="+peer.name)
		}
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
		validPeers = append(validPeers, peer)
	}

	return strings.Join(lines, "\n") + "\n", validPeers, warnings
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
	case "name":
		return "Name"
	default:
		return strings.TrimSpace(key)
	}
}

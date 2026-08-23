package main

import (
	"archive/zip"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func repeatedKeyBase64(b byte) string {
	return base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func repeatedKeyHex(b byte) string {
	return hex.EncodeToString(bytes.Repeat([]byte{b}, 32))
}

func TestParseTunnelConfigFromConf(t *testing.T) {
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + repeatedKeyBase64(0x11),
		"ListenPort = 51820",
		"MTU = 1420",
		"Address = 192.168.189.160/24",
		"",
		"[Peer]",
		"PublicKey = " + repeatedKeyBase64(0x22),
		"PresharedKey = " + repeatedKeyBase64(0x33),
		"AllowedIPs = 192.168.189.1/32, 192.168.189.2/32",
		"Endpoint = example.com:51820",
		"PersistentKeepalive = 25",
		"",
		"[Peer]",
		"PublicKey = " + repeatedKeyBase64(0x44),
		"AllowedIPs = 10.0.0.0/24",
		"PersistentKeepalive = off",
		"",
	}, "\n")

	cfg, err := parseTunnelConfig([]byte(conf), "test.conf")
	if err != nil {
		t.Fatalf("parseTunnelConfig returned error: %v", err)
	}

	if cfg.MTU != 1420 {
		t.Fatalf("expected MTU 1420, got %d", cfg.MTU)
	}

	if got, want := cfg.Source, "test.conf"; got != want {
		t.Fatalf("expected source %q, got %q", want, got)
	}

	if got, want := cfg.InterfaceName, "test"; got != want {
		t.Fatalf("expected interface name %q, got %q", want, got)
	}

	if got, want := cfg.IgnoredFields, []string{"Interface.Address"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("expected ignored fields %v, got %v", want, got)
	}

	wantUAPI := strings.Join([]string{
		"private_key=" + repeatedKeyHex(0x11),
		"listen_port=51820",
		"replace_peers=true",
		"public_key=" + repeatedKeyHex(0x22),
		"preshared_key=" + repeatedKeyHex(0x33),
		"protocol_version=1",
		"replace_allowed_ips=true",
		"allowed_ip=192.168.189.1/32",
		"allowed_ip=192.168.189.2/32",
		"endpoint=example.com:51820",
		"persistent_keepalive_interval=25",
		"public_key=" + repeatedKeyHex(0x44),
		"protocol_version=1",
		"replace_allowed_ips=true",
		"allowed_ip=10.0.0.0/24",
		"persistent_keepalive_interval=0",
		"",
	}, "\n")

	if got := cfg.UAPI; got != wantUAPI {
		t.Fatalf("unexpected UAPI output:\nwant:\n%s\ngot:\n%s", wantUAPI, got)
	}
}

func TestLoadTunnelConfigsFromZip(t *testing.T) {
	dir := t.TempDir()
	zipPath := filepath.Join(dir, "config.zip")

	f, err := os.Create(zipPath)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	zw := zip.NewWriter(f)
	files := map[string]string{
		"notes.txt":   "ignore me",
		"wgtun1.conf": "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x55) + "\n",
		"wgtun0.conf": "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x66) + "\nMTU = 1500\n",
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
		t.Fatalf("zip close: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("file close: %v", err)
	}

	cfgs, err := loadTunnelConfigs(zipPath)
	if err != nil {
		t.Fatalf("loadTunnelConfigs returned error: %v", err)
	}

	if got, want := len(cfgs), 2; got != want {
		t.Fatalf("expected %d configs, got %d", want, got)
	}

	if cfgs[0].MTU != 1500 {
		t.Fatalf("expected first MTU 1500, got %d", cfgs[0].MTU)
	}

	wantPrefix := "private_key=" + repeatedKeyHex(0x66)
	if !strings.HasPrefix(cfgs[0].UAPI, wantPrefix) {
		t.Fatalf("expected first UAPI to start with %q, got %q", wantPrefix, cfgs[0].UAPI)
	}

	if got, want := cfgs[0].InterfaceName, "wgtun0"; got != want {
		t.Fatalf("expected first interface name %q, got %q", want, got)
	}

	if got, want := cfgs[1].InterfaceName, "wgtun1"; got != want {
		t.Fatalf("expected second interface name %q, got %q", want, got)
	}

	if !strings.Contains(cfgs[0].Source, "wgtun0.conf") {
		t.Fatalf("expected first source to mention wgtun0.conf, got %q", cfgs[0].Source)
	}
}

func TestLoadTunnelConfigsFromConf(t *testing.T) {
	dir := t.TempDir()
	confPath := filepath.Join(dir, "office.conf")
	body := "[Interface]\nPrivateKey = " + repeatedKeyBase64(0x77) + "\n"
	if err := os.WriteFile(confPath, []byte(body), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfgs, err := loadTunnelConfigs(confPath)
	if err != nil {
		t.Fatalf("loadTunnelConfigs returned error: %v", err)
	}

	if got, want := len(cfgs), 1; got != want {
		t.Fatalf("expected %d config, got %d", want, got)
	}

	if got, want := cfgs[0].InterfaceName, "office"; got != want {
		t.Fatalf("expected interface name %q, got %q", want, got)
	}
}

func TestDescribeTunnelConfig(t *testing.T) {
	conf := strings.Join([]string{
		"[Interface]",
		"PrivateKey = " + repeatedKeyBase64(0x11),
		"ListenPort = 51820",
		"MTU = 1420",
		"Address = 192.168.189.160/24",
		"",
		"[Peer]",
		"PublicKey = " + repeatedKeyBase64(0x22),
		"AllowedIPs = 192.168.189.1/32, 192.168.189.2/32",
		"Endpoint = example.com:51820",
		"PersistentKeepalive = 25",
		"",
	}, "\n")

	cfg, err := parseTunnelConfig([]byte(conf), "test.conf")
	if err != nil {
		t.Fatalf("parseTunnelConfig returned error: %v", err)
	}

	summary := describeTunnelConfig(cfg)
	if !strings.Contains(summary, "接口=test") {
		t.Fatalf("summary missing interface name: %q", summary)
	}
	if !strings.Contains(summary, "MTU=1420") {
		t.Fatalf("summary missing MTU: %q", summary)
	}
	if !strings.Contains(summary, "ListenPort=51820") {
		t.Fatalf("summary missing listen port: %q", summary)
	}
	if !strings.Contains(summary, "Peer数=1") {
		t.Fatalf("summary missing peer count: %q", summary)
	}
	if !strings.Contains(summary, "AllowedIPs数=2") {
		t.Fatalf("summary missing allowed ip count: %q", summary)
	}
	if !strings.Contains(summary, "忽略字段=Interface.Address") {
		t.Fatalf("summary missing ignored fields: %q", summary)
	}

	peerSummary := describePeerConfig(cfg.Peers[0])
	if !strings.Contains(peerSummary, "公钥=222222...222222") {
		t.Fatalf("peer summary missing abbreviated key: %q", peerSummary)
	}
	if !strings.Contains(peerSummary, "AllowedIPs=192.168.189.1/32,192.168.189.2/32") {
		t.Fatalf("peer summary missing allowed ips: %q", peerSummary)
	}
	if !strings.Contains(peerSummary, "Endpoint=example.com:51820") {
		t.Fatalf("peer summary missing endpoint: %q", peerSummary)
	}
	if !strings.Contains(peerSummary, "PersistentKeepalive=25") {
		t.Fatalf("peer summary missing keepalive: %q", peerSummary)
	}
}

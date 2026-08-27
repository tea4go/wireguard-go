//go:build !windows && !linux && !darwin

package main

func startHostNetworkMonitor(func(int, []string), map[int]string) (hostNetworkMonitor, error) {
	return nil, nil
}

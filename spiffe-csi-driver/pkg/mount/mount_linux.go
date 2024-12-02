package mount

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const (
	msBind uintptr = unix.MS_BIND
)

func BindMountRW(source, target string) error {
	return unix.Mount(source, target, "none", msBind, "")
}

func Unmount(target string) error {
	return unix.Unmount(target, 0)
}

func IsMountPoint(path string) (bool, error) {
	mounts, err := parseMountInfo("/proc/self/mountinfo")
	if err != nil {
		return false, fmt.Errorf("failed to enumerate mounts: %w", err)
	}
	for _, mount := range mounts {
		if mount.MountPoint == path {
			return true, nil
		}
	}
	return false, nil
}

type mountInfo struct {
	MountID    string
	ParentID   string
	DevID      string
	Root       string
	MountPoint string
}

func parseMountInfo(path string) ([]mountInfo, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("unable to open mount info: %w", err)
	}
	defer f.Close()

	var mounts []mountInfo
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		mount, err := parseMountInfoLine(scanner.Text())
		if err != nil {
			continue
		}
		mounts = append(mounts, mount)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to scan mount info: %w", err)
	}
	return mounts, nil
}

func parseMountInfoLine(line string) (mountInfo, error) {
	fields := strings.Fields(line)
	if len(fields) < 5 {
		return mountInfo{}, fmt.Errorf("mount info line has too few fields")
	}

	return mountInfo{
		MountID:    fields[0],
		ParentID:   fields[1],
		DevID:      fields[2],
		Root:       unescapeOctal(fields[3]),
		MountPoint: unescapeOctal(fields[4]),
	}, nil
}

var reOctal = regexp.MustCompile(`\\([0-7]{3})`)

func unescapeOctal(s string) string {
	return reOctal.ReplaceAllStringFunc(s, func(oct string) string {
		r, _ := strconv.ParseUint(oct[1:], 8, 64)
		return string(rune(r))
	})
}

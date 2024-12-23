package driver

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func validatePath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("path must be absolute: %s", path)
	}

	// Clean the path and check if it changed
	cleanPath := filepath.Clean(path)
	if cleanPath != path {
		return fmt.Errorf("path contains invalid elements: %s", path)
	}

	// Check for path traversal attempts
	if strings.Contains(path, "..") {
		return fmt.Errorf("path contains forbidden elements: %s", path)
	}

	return nil
}

func secureCreateDir(path string, mode os.FileMode) error {
	if err := os.MkdirAll(path, mode); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Ensure permissions are set correctly
	if err := os.Chmod(path, mode); err != nil {
		return fmt.Errorf("failed to set directory permissions: %w", err)
	}

	return nil
}

func validateSocketFile(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("failed to stat socket file: %w", err)
	}

	mode := info.Mode().Perm()
	if mode > socketFileMode {
		return fmt.Errorf("socket file has too permissive mode: %o", mode)
	}

	return nil
}

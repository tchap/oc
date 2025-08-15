package rsync

import (
	"fmt"
	"os"
	"sort"
	"time"
)

// localFileDiscoverer implements fileDiscoverer interface for local directories.
type localFileDiscoverer struct{}

func newLocalFileDiscoverer() localFileDiscoverer {
	return localFileDiscoverer{}
}

func (discoverer localFileDiscoverer) DiscoverFiles(basePath string, last uint) ([]string, error) {
	entries, err := os.ReadDir(basePath)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory %s: %w", basePath, err)
	}

	type fileInfo struct {
		name    string
		modTime time.Time
	}

	files := make([]fileInfo, 0, len(entries))
	for _, entry := range entries {
		if entry.IsDir() {
			continue // Skip directories, only process regular files.
		}

		info, err := entry.Info()
		if err != nil {
			return nil, fmt.Errorf("failed to get file info for %s: %w", entry.Name(), err)
		}

		files = append(files, fileInfo{
			name:    entry.Name(),
			modTime: info.ModTime(),
		})
	}

	// Sort by modification time (newest first).
	sort.Slice(files, func(i, j int) bool {
		return files[i].modTime.After(files[j].modTime)
	})

	// Limit to the latest N files.
	if len(files) > int(last) {
		files = files[:last]
	}

	// Extract just the file names (relative paths).
	result := make([]string, len(files))
	for i, file := range files {
		result[i] = file.name
	}
	return result, nil
}

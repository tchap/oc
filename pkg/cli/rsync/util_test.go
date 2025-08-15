package rsync

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"k8s.io/apimachinery/pkg/util/sets"
)

// TestRsyncLastFlags tests the rsyncLastFlags function with mocked file discovery.
func TestRsyncLastFlags(t *testing.T) {
	testCases := []struct {
		name            string
		rsyncLast       uint
		discoveredFiles []string
		discoveryError  error
		expectedFlags   []string
		expectedError   bool
	}{
		{
			name:          "empty flags on last unset",
			rsyncLast:     0,
			expectedFlags: nil,
		},
		{
			name:            "discovery with no files",
			rsyncLast:       3,
			discoveredFiles: []string{},
			expectedFlags:   []string{},
		},
		{
			name:      "discovery with 1 file only",
			rsyncLast: 1,
			discoveredFiles: []string{
				"single.log",
			},
			expectedFlags: []string{
				"--include=single.log",
				"--exclude=*",
			},
		},
		{
			name:      "discovery with 3 files",
			rsyncLast: 3,
			discoveredFiles: []string{
				"newest.log",
				"middle.log",
				"oldest.log",
			},
			expectedFlags: []string{
				"--include=newest.log",
				"--include=middle.log",
				"--include=oldest.log",
				"--exclude=*",
			},
		},
		{
			name:      "discovery with more files requested than available",
			rsyncLast: 10,
			discoveredFiles: []string{
				"newest.log",
				"middle.log",
				"oldest.log",
				"another.log",
			},
			expectedFlags: []string{
				"--include=newest.log",
				"--include=middle.log",
				"--include=oldest.log",
				"--include=another.log",
				"--exclude=*",
			},
		},
		{
			name:           "discovery fails with error",
			rsyncLast:      3,
			discoveryError: errors.New("command failed"),
			expectedError:  true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create options with mock file discoverer.
			options := &RsyncOptions{
				RsyncLast: tc.rsyncLast,
				Source:    &PathSpec{Path: "/test/path"},
				fileDiscovery: &mockFileDiscoverer{
					files: tc.discoveredFiles,
					err:   tc.discoveryError,
				},
			}

			flags, err := rsyncLastFlags(options)
			if tc.expectedError {
				if err == nil {
					t.Fatal("expected error but got none")
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}

			if !cmp.Equal(flags, tc.expectedFlags) {
				t.Errorf("expected flags mismatch: \n%s\n", cmp.Diff(tc.expectedFlags, flags))
			}
		})
	}
}

// TestRsyncFlagsFromOptions tests the rsyncFlagsFromOptions function with various option combinations.
func TestRsyncFlagsFromOptions(t *testing.T) {
	testCases := []struct {
		name          string
		options       *RsyncOptions
		expectedFlags sets.Set[string]
	}{
		{
			name:          "basic options with no special flags",
			options:       &RsyncOptions{},
			expectedFlags: sets.New("-v"),
		},
		{
			name: "quiet option enabled",
			options: &RsyncOptions{
				Quiet: true,
			},
			expectedFlags: sets.New("-q"),
		},
		{
			name: "delete option enabled",
			options: &RsyncOptions{
				Delete: true,
			},
			expectedFlags: sets.New("-v", "--delete"),
		},
		{
			name: "compress option enabled",
			options: &RsyncOptions{
				Compress: true,
			},
			expectedFlags: sets.New("-v", "-z"),
		},
		{
			name: "progress option enabled",
			options: &RsyncOptions{
				RsyncProgress: true,
			},
			expectedFlags: sets.New("-v", "--progress"),
		},
		{
			name: "no-perms option enabled",
			options: &RsyncOptions{
				RsyncNoPerms: true,
			},
			expectedFlags: sets.New("-v", "--no-perms"),
		},
		{
			name: "include patterns",
			options: &RsyncOptions{
				RsyncInclude: []string{"*.log", "*.txt"},
			},
			expectedFlags: sets.New("-v", "--include=*.log", "--include=*.txt"),
		},
		{
			name: "exclude patterns",
			options: &RsyncOptions{
				RsyncExclude: []string{"*.tmp", "*.bak"},
			},
			expectedFlags: sets.New("-v", "--exclude=*.tmp", "--exclude=*.bak"),
		},
		{
			name: "multiple options combined",
			options: &RsyncOptions{
				Quiet:         true,
				Delete:        true,
				Compress:      true,
				RsyncProgress: true,
				RsyncNoPerms:  true,
				RsyncInclude:  []string{"*.log"},
				RsyncExclude:  []string{"*.tmp"},
			},
			expectedFlags: sets.New("-q", "--delete", "-z", "--progress", "--no-perms",
				"--include=*.log", "--exclude=*.tmp"),
		},
		{
			name: "rsyncLast with successful file discovery",
			options: &RsyncOptions{
				RsyncLast: 2,
				Source:    &PathSpec{Path: "/test/path"},
				fileDiscovery: &mockFileDiscoverer{
					files: []string{"newest.log", "middle.log"},
				},
			},
			expectedFlags: sets.New("-v", "--include=newest.log", "--include=middle.log", "--exclude=*"),
		},
		{
			name: "rsyncLast with no files found",
			options: &RsyncOptions{
				RsyncLast: 3,
				Source:    &PathSpec{Path: "/test/empty"},
				fileDiscovery: &mockFileDiscoverer{
					files: []string{},
				},
			},
			expectedFlags: sets.New("-v"),
		},
		{
			name: "rsyncLast with discovery error should not cause complete failure",
			options: &RsyncOptions{
				RsyncLast: 2,
				Source:    &PathSpec{PodName: "test-pod", Path: "/test/error"},
				fileDiscovery: &mockFileDiscoverer{
					err: errors.New("discovery failed"),
				},
			},
			expectedFlags: sets.New("-v"),
		},
		{
			name: "rsyncLast with include/exclude patterns and file discovery",
			options: &RsyncOptions{
				RsyncInclude: []string{"*.old"},
				RsyncExclude: []string{"*.tmp"},
				RsyncLast:    2,
				Source:       &PathSpec{PodName: "test-pod", Path: "/test/path"},
				fileDiscovery: &mockFileDiscoverer{
					files: []string{"newest.log", "middle.log"},
				},
			},
			expectedFlags: sets.New("-v", "--include=*.old", "--exclude=*.tmp",
				"--include=newest.log", "--include=middle.log", "--exclude=*"),
		},
		{
			name: "all options enabled with file discovery",
			options: &RsyncOptions{
				Quiet:         false,
				Delete:        true,
				Compress:      true,
				RsyncProgress: true,
				RsyncNoPerms:  true,
				RsyncInclude:  []string{"*.log"},
				RsyncExclude:  []string{"*.tmp"},
				RsyncLast:     1,
				Source:        &PathSpec{PodName: "test-pod", Path: "/test/path"},
				fileDiscovery: &mockFileDiscoverer{
					files: []string{"single.log"},
				},
			},
			expectedFlags: sets.New("-v", "--delete", "-z", "--progress", "--no-perms",
				"--include=*.log", "--exclude=*.tmp", "--include=single.log", "--exclude=*"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			flags := rsyncFlagsFromOptions(tc.options)
			actualFlags := sets.New(flags...)

			if !actualFlags.Equal(tc.expectedFlags) {
				t.Errorf("flags mismatch:\nexpected: %v\nactual: %v\nmissing: %v\nunexpected: %v",
					tc.expectedFlags.UnsortedList(),
					actualFlags.UnsortedList(),
					tc.expectedFlags.Difference(actualFlags).UnsortedList(),
					actualFlags.Difference(tc.expectedFlags).UnsortedList())
			}
		})
	}
}

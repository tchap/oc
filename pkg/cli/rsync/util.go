package rsync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"

	"k8s.io/klog/v2"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/kubectl/pkg/cmd/util/podcmd"
)

var (
	testRsyncCommand = []string{"rsync", "--version"}
	testTarCommand   = []string{"tar", "--version"}
)

// executeWithLogging will execute a command and log its output
func executeWithLogging(e executor, cmd []string) error {
	w := &bytes.Buffer{}
	err := e.Execute(cmd, nil, w, w)
	klog.V(4).Infof("%s", w.String())
	klog.V(4).Infof("error: %v", err)
	return err
}

// isWindows returns true if the current platform is windows
func isWindows() bool {
	return runtime.GOOS == "windows"
}

// hasLocalRsync returns true if rsync is in current exec path
func hasLocalRsync() bool {
	_, err := exec.LookPath("rsync")
	if err != nil {
		return false
	}
	return true
}

func isExitError(err error) bool {
	if err == nil {
		return false
	}
	_, exitErr := err.(*exec.ExitError)
	return exitErr
}

func checkRsync(e executor) error {
	return executeWithLogging(e, testRsyncCommand)
}

func checkTar(e executor) error {
	return executeWithLogging(e, testTarCommand)
}

func rsyncFlagsFromOptions(o *RsyncOptions) []string {
	flags := []string{}
	if o.Quiet {
		flags = append(flags, "-q")
	} else {
		flags = append(flags, "-v")
	}
	if o.Delete {
		flags = append(flags, "--delete")
	}
	if o.Compress {
		flags = append(flags, "-z")
	}
	if len(o.RsyncInclude) > 0 {
		for _, include := range o.RsyncInclude {
			flags = append(flags, fmt.Sprintf("--include=%s", include))
		}
	}
	if len(o.RsyncExclude) > 0 {
		for _, exclude := range o.RsyncExclude {
			flags = append(flags, fmt.Sprintf("--exclude=%s", exclude))
		}
	}
	if o.RsyncProgress {
		flags = append(flags, "--progress")
	}
	if o.RsyncNoPerms {
		flags = append(flags, "--no-perms")
	}
	return flags
}

// rsyncFlagsFromOptionsWithLast generates rsync flags including --last file limiting logic
func rsyncFlagsFromOptionsWithLast(o *RsyncOptions, remoteExecutor executor) ([]string, error) {
	flags := rsyncFlagsFromOptions(o)

	// Handle --last logic by generating additional exclude patterns
	if o.RsyncLast > 0 {
		excludePatterns, err := generateExcludePatterns(o.Source, o.RsyncLast, remoteExecutor)
		if err != nil {
			return nil, fmt.Errorf("failed to generate exclude patterns for --last=%d: %v", o.RsyncLast, err)
		}

		// Add the generated exclude patterns to existing excludes
		for _, exclude := range excludePatterns {
			flags = append(flags, fmt.Sprintf("--exclude=%s", exclude))
		}

		if len(excludePatterns) > 0 {
			klog.V(3).Infof("Applied --last=%d: added %d exclude patterns", o.RsyncLast, len(excludePatterns))
		}
	}

	return flags, nil
}

func tarFlagsFromOptions(o *RsyncOptions) []string {
	flags := []string{}
	if !o.Quiet {
		flags = append(flags, "-v")
	}
	if len(o.RsyncInclude) > 0 {
		for _, include := range o.RsyncInclude {
			flags = append(flags, fmt.Sprintf("**/%s", include))
		}

		// if we have explicit files or a pattern of filenames to include,
		// maintain similar behavior to tar, and include anything else
		// that would have otherwise been included
		flags = append(flags, "*")
	}
	if len(o.RsyncExclude) > 0 {
		for _, exclude := range o.RsyncExclude {
			flags = append(flags, fmt.Sprintf("--exclude=%s", exclude))
		}
	}
	return flags
}

func rsyncSpecificFlags(o *RsyncOptions) []string {
	flags := []string{}
	if o.RsyncProgress {
		flags = append(flags, "--progress")
	}
	if o.RsyncNoPerms {
		flags = append(flags, "--no-perms")
	}
	if o.Compress {
		flags = append(flags, "-z")
	}
	return flags
}

// generateExcludePatterns discovers files in the source directory and generates
// exclude patterns to limit the transfer to only the latest N files based on modification time.
// It returns additional exclude patterns that should be added to the existing excludes.
func generateExcludePatterns(source *PathSpec, last uint, remoteExecutor executor) ([]string, error) {
	if last == 0 {
		return nil, nil // No limit specified
	}

	var allFiles []string
	var err error

	if source.Local() {
		allFiles, err = discoverLocalFiles(source.Path)
	} else {
		allFiles, err = discoverRemoteFiles(source.Path, remoteExecutor)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to discover files: %v", err)
	}

	if len(allFiles) <= int(last) {
		// If we have fewer files than the limit, no need to exclude anything
		return nil, nil
	}

	// Get files to exclude (all except the latest N)
	filesToExclude := allFiles[last:]

	// Convert file paths to exclude patterns relative to source
	excludePatterns := make([]string, 0, len(filesToExclude))
	for _, file := range filesToExclude {
		// Convert absolute path to relative pattern for rsync
		relativePath, err := makeRelativePath(source.Path, file)
		if err != nil {
			klog.V(4).Infof("Warning: failed to make relative path for %s: %v", file, err)
			continue
		}
		excludePatterns = append(excludePatterns, relativePath)
	}

	klog.V(3).Infof("Generated %d exclude patterns to limit to latest %d files", len(excludePatterns), last)
	return excludePatterns, nil
}

// discoverLocalFiles finds all files in a local directory, sorted by modification time (newest first)
func discoverLocalFiles(basePath string) ([]string, error) {
	cmd := exec.Command("find", basePath, "-type", "f", "-printf", "%T@ %p\n")
	output, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("failed to execute find command: %v", err)
	}

	return parseAndSortFiles(string(output))
}

// discoverRemoteFiles finds all files in a remote directory, sorted by modification time (newest first)
func discoverRemoteFiles(basePath string, executor executor) ([]string, error) {
	var output bytes.Buffer
	var errOutput bytes.Buffer

	// Use find to get files with timestamps, then sort by timestamp
	cmd := []string{"find", basePath, "-type", "f", "-printf", "%T@ %p\\n"}
	err := executor.Execute(cmd, nil, &output, &errOutput)
	if err != nil {
		return nil, fmt.Errorf("failed to execute remote find command: %v, stderr: %s", err, errOutput.String())
	}

	return parseAndSortFiles(output.String())
}

// parseAndSortFiles parses the output from find command and returns files sorted by modification time (newest first)
func parseAndSortFiles(findOutput string) ([]string, error) {
	if strings.TrimSpace(findOutput) == "" {
		return nil, nil
	}

	lines := strings.Split(strings.TrimSpace(findOutput), "\n")
	type fileInfo struct {
		timestamp float64
		path      string
	}

	files := make([]fileInfo, 0, len(lines))
	for _, line := range lines {
		if line == "" {
			continue
		}

		parts := strings.SplitN(line, " ", 2)
		if len(parts) != 2 {
			klog.V(4).Infof("Warning: skipping malformed find output line: %s", line)
			continue
		}

		timestamp, err := strconv.ParseFloat(parts[0], 64)
		if err != nil {
			klog.V(4).Infof("Warning: failed to parse timestamp %s: %v", parts[0], err)
			continue
		}

		files = append(files, fileInfo{
			timestamp: timestamp,
			path:      parts[1],
		})
	}

	// Sort by timestamp (newest first)
	sort.Slice(files, func(i, j int) bool {
		return files[i].timestamp > files[j].timestamp
	})

	// Extract just the file paths
	result := make([]string, len(files))
	for i, file := range files {
		result[i] = file.path
	}

	return result, nil
}

// makeRelativePath converts an absolute file path to a path relative to the base directory
func makeRelativePath(basePath, filePath string) (string, error) {
	// Clean the paths to handle any ".." or extra slashes
	cleanBase := filepath.Clean(basePath)
	cleanFile := filepath.Clean(filePath)

	// Check if the file is actually under the base path
	if !strings.HasPrefix(cleanFile, cleanBase) {
		return "", fmt.Errorf("file %s is not under base path %s", filePath, basePath)
	}

	// Calculate relative path
	rel, err := filepath.Rel(cleanBase, cleanFile)
	if err != nil {
		return "", err
	}

	return rel, nil
}

type podAPIChecker struct {
	client        kubernetes.Interface
	namespace     string
	podName       string
	containerName string
	quiet         bool
	stdErr        io.Writer
}

// CheckPod will check if pods exists in the provided context and has a required container running
func (p podAPIChecker) CheckPod() error {
	pod, err := p.client.CoreV1().Pods(p.namespace).Get(context.TODO(), p.podName, metav1.GetOptions{})
	if err != nil {
		return err
	}

	if pod.Status.Phase == corev1.PodSucceeded || pod.Status.Phase == corev1.PodFailed {
		return fmt.Errorf("cannot exec into a container in a completed pod; current phase is %s", pod.Status.Phase)
	}
	if pod.DeletionTimestamp != nil {
		return fmt.Errorf("pod %v is getting deleted", p.podName)
	}

	container, err := podcmd.FindOrDefaultContainerByName(pod, p.containerName, p.quiet, p.stdErr)
	if err != nil {
		return err
	}
	for _, containerStatus := range pod.Status.ContainerStatuses {
		if containerStatus.Name == container.Name {
			if containerStatus.State.Running == nil {
				return fmt.Errorf("container %v is not running", p.containerName)
			}
			break
		}
	}
	return nil
}

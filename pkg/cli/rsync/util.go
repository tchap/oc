package rsync

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os/exec"
	"runtime"

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

	// Generate additional flags for --last.
	lastFlags, err := rsyncLastFlags(o)
	if err != nil {
		// If we can't generate the include patterns, fall back to basic flags
		// and log the error, but don't fail the entire operation.
		klog.Infof("Warning: failed to apply --last filtering: %v", err)
	} else {
		flags = append(flags, lastFlags...)
	}
	return flags
}

// rsyncLastFlags generates rsync flags for the --last option by creating include patterns for the N most recently modified files.
func rsyncLastFlags(o *RsyncOptions) ([]string, error) {
	if o.RsyncLast <= 0 {
		return nil, nil
	}

	// Handle --last logic by discovering the latest N files.
	filenames, err := o.fileDiscovery.DiscoverFiles(o.Source.Path, o.RsyncLast)
	if err != nil {
		return nil, fmt.Errorf("failed to discover files for --last=%d: %w", o.RsyncLast, err)
	}

	// Add include patterns for the discovered files.
	flags := make([]string, 0, len(filenames)+1)
	for _, filename := range filenames {
		flags = append(flags, fmt.Sprintf("--include=%s", filename))
	}

	// Add exclude all to ensure only included files are copied.
	if len(filenames) > 0 {
		flags = append(flags, "--exclude=*")
		klog.V(3).Infof("Applied --last=%d: added %d include patterns", o.RsyncLast, len(filenames))
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

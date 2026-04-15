package rsync

import (
	"io"
	"net/http"
	"net/url"

	"k8s.io/apimachinery/pkg/util/httpstream"
	"k8s.io/client-go/kubernetes"
	restclient "k8s.io/client-go/rest"
	"k8s.io/client-go/tools/portforward"
	"k8s.io/client-go/transport/spdy"
	cmdutil "k8s.io/kubectl/pkg/cmd/util"
)

// portForwarder starts port forwarding to a given pod
type portForwarder struct {
	Namespace string
	PodName   string
	Client    kubernetes.Interface
	Config    *restclient.Config
	Out       io.Writer
	ErrOut    io.Writer
}

// ensure that portForwarder implements the forwarder interface
var _ forwarder = &portForwarder{}

// ForwardPorts will forward a set of ports from a pod, the stopChan will stop the forwarding
// when it's closed or receives a struct{}
func (f *portForwarder) ForwardPorts(ports []string, stopChan <-chan struct{}) error {
	req := f.Client.CoreV1().RESTClient().Post().
		Resource("pods").
		Namespace(f.Namespace).
		Name(f.PodName).
		SubResource("portforward")

	dialer, err := createDialer("POST", req.URL(), f.Config)
	if err != nil {
		return err
	}

	// TODO: Make os.Stdout/Stderr configurable
	readyChan := make(chan struct{})
	fw, err := portforward.New(dialer, ports, stopChan, readyChan, f.Out, f.ErrOut)
	if err != nil {
		return err
	}
	errChan := make(chan error)
	go func() { errChan <- fw.ForwardPorts() }()
	select {
	case <-readyChan:
		return nil
	case err = <-errChan:
		return err
	}
}

// createDialer creates a dialer with WebSocket support and SPDY fallback,
// mirroring the unexported createDialer in upstream kubectl port-forward:
// https://github.com/kubernetes/kubectl/blob/master/pkg/cmd/portforward/portforward.go
func createDialer(method string, url *url.URL, config *restclient.Config) (httpstream.Dialer, error) {
	transport, upgrader, err := spdy.RoundTripperFor(config)
	if err != nil {
		return nil, err
	}
	dialer := spdy.NewDialer(upgrader, &http.Client{Transport: transport}, method, url)
	if !cmdutil.PortForwardWebsockets.IsDisabled() {
		tunnelingDialer, err := portforward.NewSPDYOverWebsocketDialer(url, config)
		if err != nil {
			return nil, err
		}
		dialer = portforward.NewFallbackDialer(tunnelingDialer, dialer, func(err error) bool {
			return httpstream.IsUpgradeFailure(err) || httpstream.IsHTTPSProxyError(err)
		})
	}
	return dialer, nil
}

// newPortForwarder creates a new forwarder for use with rsync
func newPortForwarder(o *RsyncOptions) forwarder {
	return &portForwarder{
		Namespace: o.Namespace,
		PodName:   o.PodName(),
		Client:    o.Client,
		Config:    o.Config,
		Out:       o.Out,
		ErrOut:    o.ErrOut,
	}
}

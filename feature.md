# RFE-2627: WebSocket Support for oc Streaming Commands

## Problem

`oc rsh`, `oc exec`, `oc attach`, and related commands use the SPDY protocol
for streaming connections. SPDY is obsolete and no longer supported by modern
browsers and proxies, which breaks deployments that place a reverse proxy in
front of the OpenShift API.

See https://redhat.atlassian.net/browse/RFE-2627

## Current State

Upstream kubectl/client-go (vendored at v0.35.2) already implements WebSocket
support with automatic SPDY fallback as part of KEP-4006
(https://github.com/kubernetes/enhancements/tree/master/keps/sig-api-machinery/4006-transition-spdy-to-websockets).

Most oc commands inherit this automatically because they are kubectl wrappers
or embed kubectl's options structs:

| Command          | How it gets WebSocket support                                      |
|------------------|--------------------------------------------------------------------|
| `oc exec`        | kubectl wrapper, upstream `createExecutor()` in exec package       |
| `oc attach`      | kubectl wrapper, upstream `createExecutor()` in attach package     |
| `oc rsh`         | embeds `exec.ExecOptions` with `DefaultRemoteExecutor`             |
| `oc debug`       | embeds `attach.AttachOptions`                                      |
| `oc port-forward`| kubectl wrapper, upstream `createDialer()` in portforward package  |

The remaining gap is `oc rsync`, which has its own port-forwarding
implementation in `pkg/cli/rsync/forwarder.go` that uses SPDY directly
without the WebSocket fallback.

## Feature Gates

WebSocket support is controlled by environment variables, enabled by default:

- `KUBECTL_REMOTE_COMMAND_WEBSOCKETS` -- exec, attach, rsh, debug
- `KUBECTL_PORT_FORWARD_WEBSOCKETS` -- port-forward

Setting either to `false` disables WebSocket and falls back to SPDY-only.

## Implementation Plan

### 1. Fix `oc rsync` port forwarding (`pkg/cli/rsync/forwarder.go`)

Add a `createDialer` helper mirroring the upstream unexported function from
`k8s.io/kubectl/pkg/cmd/portforward/portforward.go`. The upstream function
cannot be reused directly because it is unexported and takes a
`PortForwardOptions` struct specific to the port-forward command.

The helper creates a WebSocket-first dialer with automatic SPDY fallback,
gated by `KUBECTL_PORT_FORWARD_WEBSOCKETS` (same gate as `oc port-forward`).

This also fixes a latent bug where the error from `spdy.RoundTripperFor()`
is silently dropped.

### 2. Testing

#### What does not make sense to test

**Protocol selection (WebSocket vs SPDY)** cannot be verified in automated
tests without a real API server configured to accept only one protocol.
The oc repository does not use `envtest` or spin up real API servers in tests
-- all tests use fake clients or `httptest.Server`. Building a fake endpoint
that speaks the WebSocket upgrade protocol would mean reimplementing apiserver
upgrade negotiation logic just for a test.

The protocol negotiation and fallback logic belong to upstream client-go
(`FallbackDialer`, `NewSPDYOverWebsocketDialer`). If they break, upstream
tests catch it. Our `createDialer` is a direct copy of upstream's unexported
`createDialer` in `k8s.io/kubectl/pkg/cmd/portforward` -- there is no
oc-specific logic to unit test.

#### What to test

**Manual testing on a cluster** is the only way to verify the full path.
The protocol used can be confirmed via `klog` verbosity (`-v=4`):

- WebSocket success: logs `"Before WebSocket Upgrade Connection..."` followed
  by `"negotiated protocol: <version>"`
- SPDY fallback: logs `"fallback to secondary dialer from primary dialer err: ..."`
- SPDY-only (gate disabled): no WebSocket-related logs at all

```bash
# Create a test pod
oc run rsync-test --image=registry.access.redhat.com/ubi9/ubi -- sleep 3600
oc wait --for=condition=Ready pod/rsync-test

# Prepare test data
mkdir -p /tmp/rsync-test && echo "hello" > /tmp/rsync-test/file.txt

# Test 1: rsync-daemon with WebSocket (default)
# Expect "Before WebSocket Upgrade Connection" + "negotiated protocol" in logs
oc rsync --strategy=rsync-daemon -v=4 /tmp/rsync-test/ rsync-test:/tmp/dest 2>&1 \
  | grep -E "WebSocket|negotiated|fallback"
oc exec rsync-test -- cat /tmp/dest/file.txt  # should print "hello"

# Test 2: rsync-daemon with SPDY only
# Expect NO WebSocket-related logs
KUBECTL_PORT_FORWARD_WEBSOCKETS=false \
  oc rsync --strategy=rsync-daemon -v=4 /tmp/rsync-test/ rsync-test:/tmp/dest2 2>&1 \
  | grep -E "WebSocket|negotiated|fallback"
oc exec rsync-test -- cat /tmp/dest2/file.txt  # should print "hello"

# Test 3: default strategy (uses rsh, WebSocket via upstream exec path)
oc rsync /tmp/rsync-test/ rsync-test:/tmp/dest3
oc exec rsync-test -- cat /tmp/dest3/file.txt  # should print "hello"

# Test 4: other streaming commands covered by the RFE
oc exec rsync-test -- echo "exec works"
oc rsh rsync-test echo "rsh works"
oc debug rsync-test -- echo "debug works"

# Cleanup
oc delete pod rsync-test
```

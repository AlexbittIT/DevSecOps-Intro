# Lab 9 — Runtime Detection and Policy as Code

Falco `0.43.1` (modern-eBPF driver) on the WSL2 kernel `6.18.x-microsoft-standard-WSL2`; Conftest `0.69.0`. Target container `lab9-target` = `alpine:3.20`. Falco logged the expected WSL2 `failure while attaching TOCTOU mitigation program` lines at startup — detection still works, and the target stayed `running`.

## Task 1

### The two built-in rules from 9.2

| Rule | Priority | What triggered it |
|---|---|---|
| **Terminal shell in container** | Notice | `docker exec -t lab9-target sh -lc 'echo hello-from-shell'` — the `-t` attaches a TTY, which is what the rule keys on |
| **Read sensitive file untrusted** | Warning | `docker exec lab9-target sh -c 'cat /etc/shadow'` — a non-trusted program opening a sensitive file |

Alert lines (trimmed):
```
Notice A shell was spawned in a container with an attached terminal |
  evt_type=execve user=root user_uid=0 process=sh proc_exepath=/bin/busybox ...
Warning Sensitive file opened for reading by non-trusted program |
  file=/etc/shadow evt_type=open user=root user_uid=0 ...
```

### My rule (9.3) and the alert it produced

`labs/lab9/falco/rules/custom-rules.yaml`:
```yaml
- rule: Write to /tmp in container
  desc: A file under /tmp was opened for writing from inside a container
  condition: >
    open_write
    and container.id != "host"
    and fd.name startswith /tmp/
  output: >
    Write to /tmp inside container
    (container=%container.name container_id=%container.id image=%container.image.repository
     user=%user.name uid=%user.uid file=%fd.name proc=%proc.name cmdline=%proc.cmdline)
  priority: WARNING
  tags: [container, drift]
```

After `SIGHUP` reload and `docker exec --user 0 lab9-target sh -lc 'echo mine > /tmp/my-write.txt'`, the alert fired:
```json
{
  "priority": "Warning",
  "rule": "Write to /tmp in container",
  "output_fields": {
    "container.id": "1354457c3f26",
    "container.image.repository": "alpine",
    "container.image.tag": "3.20",
    "container.name": "lab9-target",
    "fd.name": "/tmp/my-write.txt",
    "proc.cmdline": "sh -lc echo mine > /tmp/my-write.txt",
    "proc.name": "sh",
    "user.name": "root",
    "user.uid": 0
  },
  "tags": ["container", "drift"]
}
```

### One JSON field that matters in an incident but is not in the message

**`container.image.tag`** (`"3.20"`). My human-readable output prints only `image=%container.image.repository` (`alpine`), not the tag. During an incident the exact image+tag is what tells a responder *which build* is affected and whether the same tag is running elsewhere in the fleet — `alpine:3.20` vs `alpine:3.19` is the difference between "patch it" and "already patched". (`evt.time.iso8601`, the nanosecond timestamp, is similarly in the JSON only and is what you correlate other logs against.)

### A legitimate workload this would flag, and how to keep the signal

The rule fires on *every* `/tmp` write in *every* container — during testing it immediately caught an unrelated `caddy` container writing a `runc-process` temp file. Plenty of legitimate software writes to `/tmp` constantly: package managers, build tools, Python's `tempfile`, nginx/caddy scratch files, image processing. Alerting on all of it is pure noise. I would keep the detection but narrow it: scope it to **interactive drift** rather than normal app scratch — e.g. only when the writing process is a shell (`proc.name in (sh, bash, ash)`) or an executable is dropped and then run, and add an exceptions macro listing the known-good images/processes (`caddy`, the build image, etc.). That preserves the "someone got a shell and is staging a file in /tmp" case while dropping the steady hum of applications using /tmp as designed.

## Task 2

### Pass/fail counts

| Manifest | Result |
|---|---|
| `juice-hardened.yaml` (shipped policy only) | 30 passed, 0 fail |
| `juice-hardened.yaml` (with my extra policy) | **34 passed, 0 fail, 0 warn** |
| `juice-unhardened.yaml` | 20 passed, **2 warnings, 8 failures** |
| `juice-compose.yml` | **15 passed**, 0 fail |

### Two failures mapped to their Rego rules

- `container "juice" uses disallowed :latest tag` ← the `deny` rule in `k8s-security.rego` with `endswith(c.image, ":latest")`.
- `container "juice" must set runAsNonRoot: true` ← the `deny` rule with `not c.securityContext.runAsNonRoot`.

(The other six failures map the same way: `allowPrivilegeEscalation`, `readOnlyRootFilesystem`, `capabilities.drop ALL`, and the four `resources.requests/limits.cpu/memory` rules.)

### Compose vs Kubernetes, and what the Compose pass means

The same requirement needs a separate rule per platform because the **document shapes differ**: a Compose service expresses "non-root, read-only, drop caps" as `user`, `read_only`, `cap_drop` and `security_opt`, whereas a Kubernetes container expresses the same intent under `securityContext.runAsNonRoot`, `readOnlyRootFilesystem` and `capabilities.drop` — so the Rego has to walk `input.services[_]` in one case and `input.spec.template.spec.containers[_]` in the other. That the Compose file **passes all 15** checks tells me the policy set is not merely a failure generator: it correctly green-lights an already-hardened file, which is the evidence that a *pass* is meaningful and the rules aren't just always-deny.

### My policy and the manifest that violates it

`labs/lab9/policies/extra/hardening.rego` (same `package k8s.security`, so Conftest runs it alongside the shipped rules):
```rego
# DENY: image must be pinned by digest, not a tag (shipped policy only bans :latest)
deny contains msg if {
  input.kind == "Deployment"
  c := input.spec.template.spec.containers[_]
  not contains(c.image, "@sha256:")
  msg := sprintf("container %q image must be pinned by digest (@sha256:...), not a tag", [c.name])
}
# WARN: pod explicitly turns on ServiceAccount-token auto-mount
warn contains msg if {
  input.kind == "Deployment"
  input.spec.template.spec.automountServiceAccountToken == true
  some c in input.spec.template.spec.containers
  msg := sprintf("pod of container %q should not set automountServiceAccountToken: true", [c.name])
}
```

The deny passes on the hardened manifest (it pins by `@sha256:`) and the warn passes too (the field is absent). My violating manifest `labs/lab9/manifests/k8s/violates-extra-policy.yaml` uses a tag image and sets `automountServiceAccountToken: true`.

Runs:
```
$ conftest test labs/lab9/manifests/k8s/juice-hardened.yaml --policy labs/lab9/policies --all-namespaces
34 tests, 34 passed, 0 warnings, 0 failures

$ conftest test labs/lab9/manifests/k8s/violates-extra-policy.yaml --policy labs/lab9/policies --all-namespaces
WARN - ... pod of container "juice" should not set automountServiceAccountToken: true
FAIL - ... container "juice" image must be pinned by digest (@sha256:...), not a tag
17 tests, 15 passed, 1 warning, 1 failure
```

### CI (Conftest) vs runtime (Falco) — which one I keep

For the digest-pin rule I keep **Conftest in CI**. Whether an image is pinned by digest is a static property of the manifest, knowable before anything runs, and blocking it at admission means the un-pinned image never starts — prevention beats detection for a property you can check up front, and Falco can't really enforce "pinned by digest" once the container is already running. What the runtime side still buys me: Conftest only ever sees what actually goes *through* the pipeline. Falco catches the container that bypassed it — a `kubectl run` by hand, a workload launched on a compromised node, config drift — which never faced the CI gate at all. So CI prevents the mistake in the golden path; runtime catches what went around the golden path.

## Bonus

### The rule and the alert

```yaml
- list: crypto_pool_ports
  items: [3333, 4444, 5555, 7777, 14444]
- list: crypto_miner_procs
  items: [xmrig, minerd, cpuminer, ethminer, nheqminer, cryptonight, nc, ncat, netcat]
- rule: Outbound crypto mining connection
  desc: A process in a container connected out to a typical mining-pool port
  condition: >
    evt.type = connect
    and container.id != "host"
    and fd.sport in (crypto_pool_ports)
    and proc.name in (crypto_miner_procs)
  output: >
    Outbound connection to crypto-mining pool port
    (container=%container.name container_id=%container.id image=%container.image.repository
     proc=%proc.name cmdline=%proc.cmdline user=%user.name
     connection=%fd.name dest_port=%fd.sport)
  priority: CRITICAL
  tags: [network, mitre_command_and_control, cryptomining]
```

The alert (CRITICAL), combining both signals — the mining process name *and* the pool port:
```json
{
  "priority": "Critical",
  "rule": "Outbound crypto mining connection",
  "output_fields": {
    "container.name": "lab9-target",
    "proc.name": "nc",
    "proc.cmdline": "nc -w 3 127.0.0.1 3333",
    "fd.name": "127.0.0.1:42257->127.0.0.1:3333",
    "fd.sport": 3333
  }
}
```

(On this WSL2 kernel a *refused* connect did not populate `fd.sport` — the same missing-tracepoint limitation that produces the TOCTOU warnings — so I completed the connect against a local listener on 3333 to capture the alert. The detection logic is unchanged.)

### Why a refused connection is enough, and where Falco sits

The `connect()` syscall is issued by the process — and seen by the kernel — the instant it *attempts* the connection, before any SYN/ACK comes back. Falco hooks that syscall, so it observes the attempt whether the peer accepts, resets, or the packet is dropped. The implication is that Falco sits at the **kernel/syscall boundary on the host**, not on the network path: it watches what the *process did* (its intent), not whether traffic succeeded. You cannot evade it by making the connection fail.

### The evasion, cheap vs expensive, and what to add

An attacker who reads this rule just picks a port not in my list — changing the destination port is **free**, a one-line config change in the miner. What is **expensive** to change is the behaviour underneath: a miner still has to open a sustained outbound connection *and* burn CPU doing proof-of-work; it can't mine without doing both. So I would stop anchoring on the port allowlist (the cheap signal) and add a behavioural signal (the expensive one): sustained high CPU in a container combined with any long-lived outbound connection to a newly-seen external IP, plus known miner binary names/hashes and the `/tmp` drift rule from Task 1. Catch the thing the attacker cannot stop doing, not the one port they can rename.

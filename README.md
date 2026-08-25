# netconf — IAG5 Python script service (Cisco IOS XE + NX-OS)

Generic NETCONF driver for Cisco IOS XE (CSR1000v, ISR 4000, ASR 1000, Catalyst 9000, etc.)
and Cisco NX-OS (Nexus 3K/7K/9K). One driver, one set of services — platform is resolved
per-device at runtime, not hardcoded per service.

Transport: NETCONF over SSH (port 830). Requires `netconf-yang` (IOS XE) or `feature netconf`
(NX-OS) enabled on the target device.

## Platform resolution

Resolved in this order:
1. `--platform` CLI flag (`"IOS XE"` or `"NX-OS"`, case/space/dash-insensitive)
2. Inventory attribute `platform` (e.g. Netbox `platform.name`)
3. Default: `ios-xe` (backward compatible with pre-generic invocations)

## Actions

| Action | Purpose | Notes |
|---|---|---|
| `is-alive` | Confirm device responds to NETCONF | IOS XE: reads native-model version via `<get>`. NX-OS: successful capability exchange is the proof — no NX-OS YANG container is assumed present, since supported versions span 8.2(6a) through 10.4(4). |
| `run-command` | Execute exec-mode CLI commands | IOS XE: `cisco-ia` exec RPC. NX-OS: ncclient's native `exec_command()` (legacy `nxos:1.0` namespace) — **not universally supported**; devices that only expose the native `Cisco-NX-OS-device` YANG model (confirmed on NX-OS 9.2(4)) will fail this cleanly with a message pointing at structured `<get>` instead. |
| `get-config` | Retrieve running or candidate configuration | Fully generic — `xml` format works identically on both platforms with zero platform-specific code. `text`/`set` formats go through `run-command`'s exec path (IOS XE only, currently). |
| `send-command` | Apply config and commit | See below — two input modes. |
| `reboot` | Schedule a reload | Goes through the same exec-command path as `run-command`; same NX-OS caveat applies. NX-OS `reload` interactive-confirmation behavior via `exec_command()` is unvalidated. |

## send-command: two input modes

**1. Raw CLI commands (`--command` / `--commands`)** — IOS XE only. Wraps commands in
`cli-config-data`, a Cisco IOS XE-specific tag that lets `edit-config` parse raw CLI text as
if typed at the CLI. This is *not* a generic mechanism — NX-OS has no equivalent, and calling
it with `platform=nx-os` returns a clean `NotImplementedError` rather than guessing.

**2. Raw pre-built XML (`--config_xml`)** — generic, any platform. Bypasses CLI-to-XML
conversion entirely; the driver just does `lock → edit-config → validate → commit` against
whatever `<config>` payload it's given. This is the real "generic driver" path: it works on
NX-OS as long as the caller (e.g. a workflow's Jinja2 templates) supplies XML valid for that
device's actual YANG model. Confirmed live against a Nexus 9000v device — a hand-built
`Cisco-NX-OS-device` payload was accepted, validated, and committed successfully.

### ⚠️ Confirmed-commit rollback — verified NOT reliable on at least one NX-OS image

Tested live: issued `commit(confirmed=True, timeout=10)`, sent the textbook-correct RFC 6241
RPC (`<commit><confirmed/><confirm-timeout>10</confirm-timeout></commit>`), got `<ok/>` back,
closed the session without ever sending a confirming commit. Per RFC 6241 this should roll
back immediately on session close (no `persist` was used). It did not — the change was still
live 150+ seconds later. This was confirmed to be a device-side gap, not a client bug (the
wire-level RPC was inspected and was correct). **Do not treat NX-OS commit-confirm as a proven
safety net without re-validating against the specific target hardware/software version.**

Separately: `send_command`'s `confirmed=True` path currently closes the session immediately
after starting the timer — there's no follow-up call anywhere in this driver that issues the
actual confirming commit (which would need either a same-session call or `persist`/
`persist_id` to survive across sessions). This needs to be wired up before `confirmed=True`
is relied on for real rollback protection on *any* platform, IOS XE included.

## get-config format options

`get-config` supports three output formats controlled by the `config_format` attribute in the
device's inventory record (or `--config-format` when testing locally).

| Format | How it works | Datastores | Output |
|---|---|---|---|
| `xml` | NETCONF `get-config` RPC | `running`, `candidate` | Pretty-printed XML — generic, both platforms |
| `text` | `show running-config` via exec RPC | `running` only | IOS XE text format only (currently) |
| `set` | `show running-config` via exec RPC | `running` only | IOS XE text format only (currently) |

**`xml` is the default** if `config_format` is not set.

**Subtree filter (`filter`) is only available with `xml`** — text and set formats retrieve the
full configuration and do not support filtering.

Set the format per device in Inventory Manager:

```json
"itential_driver_options": {
  "netconf": {
    "config_format": "xml"
  }
}
```

## Invocation model

**One service per operation, shared across platforms** — each service in `import.yaml` points
at the same `main.py` and sets a `NETCONF_OP` environment variable. Platform is *not* baked
into the service — it's resolved per-device from inventory at runtime, so the same
`netconf-is-alive` service works against an IOS XE device or an NX-OS device without change.

Connection parameters (`host`, `port`, `user`, `password`, `platform`, `timeout`,
`lock-timeout`, `lock-poll-interval`) come from the device's Inventory Manager record via
stdin — gateway5 pipes the `InventoryInfo` JSON to the script's stdin automatically when
invoked through an inventory action.

### Registered services

| Service name | Operation | Notes |
|---|---|---|
| `netconf-is-alive` | is-alive | No runtime args needed |
| `netconf-run-command` | run-command | Workflow passes `command`. NX-OS support device-dependent — see caveat above |
| `netconf-get-config` | get-config | Optional `source`, `filter`, `config_format` |
| `netconf-send-config` | send-command | Workflow passes `config` (multi-line block) — IOS XE only |
| `netconf-send-command` | send-command | Workflow passes `commands` (array) — IOS XE only |
| `netconf-send-config-xml` | send-command | Workflow passes `config_xml` (raw payload) — generic, any platform |
| `netconf-reboot` | reboot | Optional `at`, `message` |
| `netconf-set-config` | set-config | Config Manager remediation broker entry point |

### From iagctl

```bash
iagctl run service python-script netconf-is-alive --set platform="IOS XE"

iagctl run service python-script netconf-run-command \
  --set platform="IOS XE" --set command="show version"

iagctl run service python-script netconf-send-command \
  --set platform="IOS XE" \
  --set 'commands=["interface GigabitEthernet1","description managed-by-itential"]'

iagctl run service python-script netconf-send-config-xml \
  --set platform="NX-OS" \
  --set 'config_xml=<config><System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device">...</System></config>'

iagctl run service python-script netconf-reboot \
  --set platform="IOS XE" --set at="5"
```

### From an Inventory Manager action mapping

```json
{
  "name": "run-command",
  "action_type": "iag5-service",
  "action_config": {
    "service_name": "netconf-run-command",
    "cluster_id": "cluster-itential"
  },
  "action_parameters": {}
}
```

### Required vs optional inputs

- **Operation selector:** set by service name + `NETCONF_OP` env var (not a runtime input)
- **Platform selector:** `platform` — from CLI flag, inventory attribute, or defaults to `ios-xe`
- **Required for `netconf-run-command` and `netconf-send-command`:** `command` / `commands`
- **Required for `netconf-send-config-xml`:** `config_xml`
- **Connection fields (`host`, `user`, `password`, etc.):** resolved from inventory by default; CLI flags only when overriding
- **Unknown keys are rejected** by `additionalProperties: false`

### Direct local testing

```bash
NETCONF_OP=is-alive python main.py \
  --platform "IOS XE" --host 192.0.2.1 --user admin --password "$PASS"

NETCONF_OP=is-alive python main.py \
  --platform "NX-OS" --host 192.0.2.2 --user admin --password "$PASS"

NETCONF_OP=send-command python main.py \
  --platform "IOS XE" --host 192.0.2.1 --user admin --password "$PASS" \
  --command "interface GigabitEthernet1" \
  --command "description managed-by-itential"

NETCONF_OP=send-command python main.py \
  --platform "NX-OS" --host 192.0.2.2 --user admin --password "$PASS" \
  --config_xml '<config><System xmlns="http://cisco.com/ns/yang/cisco-nx-os-device">...</System></config>'
```

CLI flags win over stdin values when both are present.

## Candidate datastore locking (send-command)

`send-command` auto-detects whether the device advertises the candidate datastore capability.
If present, it takes an exclusive lock before loading config. If not, config is applied
directly to `running`.

| Flag | Default | Purpose |
|---|---|---|
| `--lock-timeout` | `30` | Max seconds to wait. `0` = fail immediately. |
| `--lock-poll-interval` | `2.0` | Seconds between retries. |

## Long-running commands

For commands that take longer than the default 30s session timeout, set `command_timeout` in
the inventory:

```json
"itential_driver_options": {
  "netconf": {
    "port": 830,
    "timeout": 30,
    "command_timeout": 120,
    "lock_timeout": 60,
    "lock_poll_interval": 2
  }
}
```

`command_timeout` only applies to `run-command`.

## Recommended inventory attributes

```json
{
  "name": "my-device",
  "attributes": {
    "platform": "IOS XE",
    "itential_host": "192.0.2.1",
    "itential_user": "admin",
    "itential_password": "secret",
    "itential_driver_options": {
      "netconf": {
        "port": 830,
        "timeout": 30,
        "command_timeout": 60,
        "lock_timeout": 30,
        "lock_poll_interval": 2,
        "config_format": "xml"
      }
    }
  }
}
```

## Prerequisites on the device

```
! IOS XE
netconf-yang
! Optional — enables candidate datastore, commit, dry-run:
netconf-yang feature candidate-datastore
commit

! NX-OS
feature netconf
```

Port 830 must be reachable from the IAG5 host.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python main.py --op is-alive --platform "IOS XE" --host 192.0.2.1 --user admin --password "$PASS"
```

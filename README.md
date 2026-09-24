# netconf-python — IAG5 Python script service (Cisco IOS XE)

A single-use-case NETCONF driver: **push an XML payload to a Cisco IOS XE device via
NETCONF, and render it as CLI text (or, where unavailable, a structural XML diff) for
human approval before it is committed.**

Transport: NETCONF over SSH (port 830), DMI `netconf-yang`.

**Fleet:**

| Platform | Models | N | N-1 |
|---|---|---|---|
| Catalyst access | IE 3400, IE 3500, CAT 9300/9400 | 17.15.5 | 17.12.4 |
| Catalyst core | CAT 9500 | 17.15.5 | 17.12.4 |

NX-OS is out of scope for this driver (see git history if that work resumes as a
later phase — it isn't part of this repo anymore).

## Actions

| Action | Purpose | Notes |
|---|---|---|
| `netconf-is-alive` | Confirm device responds to NETCONF | Returns JSON with `alive` and `output` (native-model version via `<get>`, e.g. `17.15`) |
| `netconf-get-config` | Retrieve running or candidate configuration | XML only |
| `netconf-get-config-clis` | Render running or candidate as CLI text | Uses `get-modelled-config-clis` (`Cisco-IOS-XE-cli-rpc`) — the device's own modelled-config-to-CLI renderer. This is the mechanism behind `netconf-preview-config`'s `preview_mode="device-rendered"` outcome. |
| `netconf-preview-config` | **The core feature.** Stage a proposed `config_xml` change, diff it against running, then discard | Never commits. See "Preview and push workflow" below. |
| `netconf-send-command` (service name: `netconf-send-config-xml`) | Apply `config_xml` for real (commit) | The only push path — see below. |
| `netconf-discard` | Discard whatever is staged in candidate | Clears a dirty candidate (e.g. one flagged by a preview call) out of band. |

## Preview and push workflow

1. **Preview:** call `netconf-preview-config` with `config_xml`. This locks candidate,
   applies the config, diffs it against running, and discards — all in one call, leaving
   zero state on the device. Returns a `diff`, a `running_hash` fingerprint, and
   `preview_mode` (see below). A human reviews the diff.
2. **Push:** once approved, call `netconf-send-config-xml` with the *same* `config_xml`,
   optionally passing `expect_running_hash` set to the `running_hash` from step 1. This
   locks candidate, discards any stray staged content, edits, and commits in one call. If
   `expect_running_hash` is set and running config has drifted since the preview captured
   its hash, the push is refused with `error_type=ConfigDrift` rather than applying an
   approved diff against config that has since moved.

There is no separate stage-then-later-finish step. `config_xml` is generated upstream
(Jinja2 or similar) once and used for both calls.

## `preview_mode`

`netconf-preview-config`'s result always includes a `preview_mode` field — never absent,
never guessed:

| Value | Meaning |
|---|---|
| `"device-rendered"` | The diff came from the device's own CLI renderer (`get-modelled-config-clis`). Expected on 17.15.5-class images. |
| `"xml-diff"` | Structural fallback: a diff of plain `get-config` XML text. Used when `get-modelled-config-clis` is unsupported — expected on 17.12.4, which most likely carries a `Cisco-IOS-XE-cli-rpc` revision that predates `get-modelled-config-clis`. |

Both modes run the identical lock/edit/validate/discard sequence — only the render-and-diff
step differs. An operator approving a change needs to know which one they're looking at.

**Unverified, TODO — do not assume:**
- Whether `Cisco-IOS-XE-cli-rpc` is present on 17.12.4, and at which revision.
- Whether `get-modelled-config-clis` exists on IE 3400 / IE 3500 at 17.15.5 (confirmed on
  17.15 generally, not on the IoT platforms).
- What `get-modelled-config-clis` silently omits per platform (Cisco's docs say
  wireless/app-hosting/telemetry aren't supported through it; whether that means an error
  or a silent omission from the render is unconfirmed). A non-empty `error-message`
  alongside a result surfaces as `warning` rather than being swallowed — but an omission
  with no `error-message` at all would currently go unnoticed.
- Realistic render duration on a CAT 9500 core config — only ~17s on a CSR1000v lab
  device is measured, a different platform family entirely from this fleet.

## Candidate datastore locking

`netconf-preview-config` and `netconf-send-command` auto-detect whether the device
advertises the candidate datastore capability (parsed from the capability URN, not a
substring match). If present, both take an exclusive lock before touching candidate. If
not, `netconf-send-command` edits `running` directly.

| Flag | Default | Purpose |
|---|---|---|
| `--lock_timeout` | `30` | Max seconds to wait. `0` = fail immediately. |
| `--lock-poll-interval` | `2.0` | Seconds between retries. |

Lock-denied retries match on `error-tag == "lock-denied"` only — not on message-string
sniffing, which was validated against exactly one 17.15 device and isn't guaranteed to
hold on a different DMI build (e.g. IE 3400 on 17.12.4). Any other RPC error during lock
acquisition is treated as fatal, not transient.

**Unverified, TODO:** whether `candidate-datastore` is available and enabled across all
four platform families on both trains.

## Dirty-candidate handling

Before staging anything, `netconf-preview-config` compares running vs candidate via plain
`get-config` (not the CLI renderer — this check must work identically regardless of
`preview_mode`). If they differ, another session has uncommitted work staged there:

- Default: refused with `error_type=DirtyCandidate` and a `dirty_diff` showing what's there.
- `force_discard=true`: discards it and proceeds. Discard happens before any lock is taken
  (`discard-changes` needs no lock, RFC 6241 §8.3.4.2).

## `expect_running_hash` drift guard

`running_hash` (from a preview call) and `expect_running_hash` (on the push call) are both
fingerprints of the running-config XML (via plain `get-config`), not of a CLI render — this
is what lets the drift guard work identically in both `preview_mode` outcomes. A push whose
`expect_running_hash` doesn't match current running config is refused with
`error_type=ConfigDrift`.

## Local development

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

NETCONF_OP=netconf-is-alive python main.py \
  --host 192.0.2.1 --user admin --password "$PASS"

NETCONF_OP=netconf-preview-config python main.py \
  --host 192.0.2.1 --user admin --password "$PASS" \
  --config_xml '<config><native xmlns="http://cisco.com/ns/yang/Cisco-IOS-XE-native">...</native></config>'

NETCONF_OP=netconf-send-command python main.py \
  --host 192.0.2.1 --user admin --password "$PASS" \
  --config_xml '<config>...</config>' \
  --expect_running_hash abcdef0123456789
```

CLI flags win over stdin values when both are present.

### Tests

```bash
python -m unittest test_main -v
```

Offline, no device needed — covers text normalization/hashing, capability parsing, and
`preview_mode` selection (including the XML-diff fallback).

## Recommended inventory attributes

```json
{
  "name": "my-device",
  "attributes": {
    "itential_host": "192.0.2.1",
    "itential_user": "admin",
    "itential_password": "secret",
    "itential_driver_options": {
      "netconf": {
        "port": 830,
        "timeout": 90,
        "lock_timeout": 30,
        "lock_poll_interval": 2
      }
    }
  }
}
```

## Prerequisites on the device

```
netconf-yang
! Optional — enables candidate datastore + commit + validate:
netconf-yang feature candidate-datastore
commit
```

Port 830 must be reachable from the IAG5 host.

**Hardening item, out of scope here:** the driver connects with `hostkey_verify=False`.
Flagged for production review, not addressed in this pass.

## Deployment notes

- **`main.py` needs no reload.** IAG5 pulls the pinned repository reference fresh on every
  service execution.
- **`import.yaml` does need a reload.** Decorators and service definitions live in the
  gateway's data store, not in git:
  ```bash
  iagctl db import import.yaml --repository netconf-python --force
  ```
- **Import never deletes.** It only adds and replaces by matching name. A service removed
  from `import.yaml` stays registered in the data store — still advertised, still showing
  its old input schema — until explicitly removed:
  ```bash
  iagctl delete service python-script <name>
  ```
  Check Platform for workflow bindings to a removed service name before deleting it.
- **This repo tracks `main`** (`reference: main` in `import.yaml`) — intentional here,
  since this repo is for testing and every push should be immediately reflected on the
  next service run. The production driver will live on a separate repo; pin *that* one's
  reference to a tag/SHA before it's used against a live customer environment, since a
  moving branch reference there would make every merge an unreviewed production deploy.

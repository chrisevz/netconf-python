# netconf-python

An Itential IAG5 Python-script driver that pushes a ready-made NETCONF `<config>` XML
payload to a Cisco device. It shows a preview first and has a safe way back. Transport is
NETCONF over SSH (port 830).

## Platform support

| Service | IOS XE | NX-OS |
|---|---|---|
| `netconf-is-alive` | verified on a device | verified on a device |
| `netconf-get-config` | verified on a device | verified on a device |
| `netconf-preview-config` | verified on a device | verified on a device (`xml-diff` preview) |
| `netconf-send-config-xml` | verified on a device | verified on a device |
| `netconf-confirm-commit` | verified on a device | offline-tested only |
| `netconf-cancel-commit` | verified on a device | verified on a device |
| `netconf-save-config` | verified on a device | offline-tested only |
| `netconf-existing-config-check` | verified on a device | not supported yet (returns `error_type=NotSupported`) |

- **verified on a device**: run successfully on a real device or lab image.
- **offline-tested only**: the code path exists and passes the unit tests, but has not yet
  been run on a device.
- **not supported yet**: the service refuses the request.

One driver, the same service names for both platforms. The platform is detected from the
YANG modules the device advertises.

Verified on IOS XE 17.15.5 (Catalyst 9500 stack) and NX-OS 10.5(5) (Nexus 9000v). Other
IOS XE models and releases (for example IE 3400 / IE 3500, 17.12.x) are untested. If the
device cannot render the preview as CLI text, the preview falls back to `xml-diff`.

## Services

Each service reads the device from the gateway inventory and returns JSON with `success`
(plus `error` and `error_type` on failure). All accept `timeout` (seconds, default 90).

| Service | What it does | Key inputs | Key outputs |
|---|---|---|---|
| `netconf-is-alive` | Checks NETCONF reachability and returns device facts | - | `alive`, `output` (software version), `platform`, `capabilities`, `persist_confirmed_commit` |
| `netconf-get-config` | Reads running or candidate config as XML | `source`, `filter` | `config` |
| `netconf-preview-config` | Stages `config_xml` in the candidate, diffs it against running, then discards it. Never commits | `config_xml`, `force_discard`, `diff`, `lock_timeout` | `diff`, `diff_rows`, `diff_stats`, `running_hash`, `preview_mode`, `timings` |
| `netconf-send-config-xml` | Pushes `config_xml` (lock, edit, validate, commit) | `config_xml`, `expect_running_hash`, `confirm_timeout`, `lock_timeout` | `commit`, `confirmed_commit`, `drift_check`; with `confirm_timeout` also `persist_id`, `confirm_deadline_utc` |
| `netconf-confirm-commit` | Makes a pending confirmed commit permanent | `persist_id` | `success` |
| `netconf-cancel-commit` | Rolls a pending confirmed commit back now | `persist_id` | `success`, `rolled_back` |
| `netconf-save-config` | Copies running to startup (write memory) | - | `method` |
| `netconf-existing-config-check` | Read-only: does the device already carry configuration? (IOS XE only) | - | `found`, `findings` (at most 20), `findings_total` |

## Typical flow

1. `netconf-preview-config` with `config_xml`. A person reviews the `diff`.
2. `netconf-send-config-xml` with the same `config_xml`, `expect_running_hash` set to the
   preview's `running_hash`, and `confirm_timeout` (seconds).
3. Verify the change, then `netconf-confirm-commit` with the returned `persist_id`
   (or `netconf-cancel-commit` to roll back).
4. `netconf-save-config` to write it to startup.

## Behaviour notes

- **The device owns the rollback timer.** With `confirm_timeout`, the push is a persistent
  confirmed commit (RFC 6241, `:confirmed-commit:1.1`). The change is live, and the device
  reverts it by itself unless `netconf-confirm-commit` arrives with the `persist_id` in
  time. A dead workflow or gateway therefore still ends in a rollback. A device without
  confirmed-commit 1.1 is refused (`error_type=NoConfirmedCommit`) before anything is
  edited. There is no fallback to a plain commit. Confirm fails if the timer has already
  run out. Save to startup only after a successful confirm. Without `confirm_timeout` the
  push is a plain commit.
- **Drift guard.** `expect_running_hash` is the `running_hash` from the preview. If the
  running config has changed since, the push is refused with `error_type=ConfigDrift`. On
  IOS XE, if the check cannot be made, the push is refused too (`DriftCheckUnavailable`).
- **Dirty candidate and locks.** If the candidate holds uncommitted changes from another
  session, preview returns `error_type=DirtyCandidate` with a `dirty_diff`.
  `force_discard=true` discards them and continues. If another session holds the lock
  longer than `lock_timeout`, the call returns `CandidateLocked`.
- **Secrets.** `netconf-preview-config` and `netconf-send-config-xml` refuse a `config_xml`
  that still contains an unresolved `$GATEWAYSECRET_` placeholder, so a literal
  placeholder is never sent to a device.
- **Existing-config check.** `netconf-existing-config-check` returns only short finding
  lines, never config text or keys.
- **`preview_mode`** is always present. `device-rendered` is the device's own CLI text
  (IOS XE 17.15.5-class images). `xml-diff` is a structural XML diff (NX-OS, and IOS XE
  images without the render RPC).
- **`diff_rows`** holds side-by-side data: changed lines plus 3 lines of context, at most
  5000 rows, as raw text (not HTML-escaped). `timings` lists the time taken per step.
- **Security.** The driver connects with `hostkey_verify=False`, so SSH host keys are not
  checked. Review this before wider production use.

## Requirements

- Python 3 with `ncclient==0.6.19` and `lxml==5.2.2` (`requirements.txt`; the versions
  tested on the gateway).
- On the device: NETCONF enabled and port 830 reachable from the gateway. On IOS XE this
  means `netconf-yang`, plus `netconf-yang feature candidate-datastore` for
  candidate/commit.
- Inventory node attributes: `itential_host`, `itential_user`, `itential_password`, and
  optionally `itential_driver_options.netconf` (`port`, `timeout`, `lock_timeout`,
  `lock_poll_interval`).

## Import into IAG5

1. Put this code in your own repository.
2. In `import.yaml`, set `url` to that repository and `reference` to a release tag. The
   gateway pulls the repository on every service run, so a branch reference would deploy
   every merge immediately.
3. Import, then check the services:
   ```bash
   iagctl db import import.yaml --repository netconf-python --force
   ```
4. Import adds and replaces by name but never deletes. List what the gateway has with
   `iagctl get services` and `iagctl get decorators`, and remove anything no longer in
   `import.yaml`. Check workflow bindings before deleting a service. Delete services
   first, then their decorators (delete does not check references):
   ```bash
   iagctl delete service <name>
   iagctl delete decorator <name>
   ```
   Older iagctl versions take `iagctl delete service python-script <name>`.

### Upgrading a gateway that already has these services

Service names have not changed. A gateway imported before the rename of
`netconf-send-config-xml` still sends the old internal op name `netconf-send-command`.
`main.py` accepts it, so nothing breaks before you re-import.

## Run locally and test

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

NETCONF_OP=netconf-is-alive python main.py --host 192.0.2.1 --user admin --password "$PASS"
NETCONF_OP=netconf-preview-config python main.py --host 192.0.2.1 --user admin \
  --password "$PASS" --config_xml '<config>...</config>'

python3 -m unittest test_main      # offline, no device needed
```

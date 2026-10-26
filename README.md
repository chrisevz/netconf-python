# netconf-python

An Itential IAG5 Python-script driver that pushes a pre-built NETCONF `<config>` XML
payload to a Cisco device, with a preview first and a safe way back. Platforms: **Cisco
IOS XE** and **NX-OS**. Transport is NETCONF over SSH (port 830).

Verified on IOS XE 17.15.5 (Catalyst 9500 stack, including the device-rendered preview and
confirmed commit) and NX-OS 10.5(5) (Nexus 9000v: is-alive, candidate get-config, xml-diff
preview, confirmed commit and cancel from a new session).

## Services

Each service reads the device from the gateway inventory and returns JSON with `success`
(plus `error` / `error_type` on failure). All accept `timeout` (seconds, default 90).

| Service | What it does | Platforms | Key inputs | Key outputs |
|---|---|---|---|---|
| `netconf-is-alive` | NETCONF reachability and device facts | IOS XE, NX-OS | - | `alive`, `output` (software version), `platform`, `capabilities`, `persist_confirmed_commit` |
| `netconf-get-config` | Read running or candidate config as XML | IOS XE, NX-OS | `source`, `filter` | `config` |
| `netconf-preview-config` | Stage `config_xml` into candidate, diff against running, discard. Never commits | IOS XE, NX-OS (NX-OS = `xml-diff`) | `config_xml`, `force_discard`, `diff`, `lock_timeout` | `diff`, `diff_rows`, `diff_stats`, `running_hash`, `preview_mode`, `timings` |
| `netconf-send-config-xml` | Push `config_xml` (lock, edit, validate, commit) | IOS XE, NX-OS | `config_xml`, `expect_running_hash`, `confirm_timeout`, `lock_timeout` | `commit`, `confirmed_commit`, `drift_check`, and with `confirm_timeout` also `persist_id`, `confirm_deadline_utc` |
| `netconf-confirm-commit` | Make a pending confirmed commit permanent | IOS XE, NX-OS | `persist_id` | `success` |
| `netconf-cancel-commit` | Roll a pending confirmed commit back now | IOS XE, NX-OS | `persist_id` | `success`, `rolled_back` |
| `netconf-save-config` | Copy running to startup (write memory) | IOS XE (`cisco-ia:save-config`, else `Cisco-IOS-XE-rpc:copy`), NX-OS (`copy_running_config_src`) | - | `method` |
| `netconf-existing-config-check` | Read-only: does the device already carry configuration? | IOS XE only (NX-OS returns `NotSupported`) | - | `found`, `findings` (capped at 20), `findings_total` |

## Typical flow

1. `netconf-preview-config` with `config_xml`. A person reviews the `diff`.
2. `netconf-send-config-xml` with the same `config_xml`, `expect_running_hash` set to the
   preview's `running_hash`, and `confirm_timeout` (seconds).
3. Verify the change, then `netconf-confirm-commit` with the returned `persist_id`
   (or `netconf-cancel-commit` to roll back).
4. `netconf-save-config` to persist to startup.

## Behavior notes

- **The device owns the rollback timer.** With `confirm_timeout`, the push is a persistent
  confirmed commit (RFC 6241, `:confirmed-commit:1.1`). The change is live, and the device
  reverts it by itself unless `netconf-confirm-commit` arrives with the `persist_id` in
  time, so a dead workflow or gateway still ends in a rollback. A device without 1.1 is
  refused (`error_type=NoConfirmedCommit`) before anything is edited; there is no fallback
  to a plain commit. Confirm fails if the timer already ran out. Save to startup only after
  a successful confirm. Without `confirm_timeout` the push is a plain commit.
- **Drift guard.** `expect_running_hash` is the `running_hash` from the preview. If running
  config changed since, the push is refused with `error_type=ConfigDrift`. If the check
  cannot be made on IOS XE it fails closed (`DriftCheckUnavailable`).
- **Dirty candidate.** If the candidate datastore holds uncommitted changes from another
  session, preview returns `error_type=DirtyCandidate` with a `dirty_diff`.
  `force_discard=true` discards them and proceeds. A lock held by another session past
  `lock_timeout` returns `CandidateLocked`.
- **Secrets.** `netconf-preview-config` and `netconf-send-config-xml` refuse a `config_xml`
  that still contains an unresolved `$GATEWAYSECRET_` placeholder, so a literal
  placeholder is never sent to a device.
- **`netconf-existing-config-check`** never returns config text or keys, only short
  finding lines.
- **`preview_mode`** is always present: `device-rendered` (the device's own CLI render,
  IOS XE 17.15.5-class images) or `xml-diff` (structural XML diff: NX-OS, and IOS XE images
  without the render RPC).
- The preview also returns `diff_rows` (side-by-side data: changed lines plus 3 lines of
  context, capped at 5000 rows, raw text, not HTML-escaped) and `timings` per step.
- The driver connects with `hostkey_verify=False`; review before wider production use.
- **Not yet verified on a device:** NX-OS `netconf-confirm-commit` and `netconf-save-config`
  (the code paths exist and are tested offline only). Other IOS XE models and trains (for
  example IE 3400 / IE 3500, 17.12.x) are untested; if the CLI render RPC is missing, the
  preview falls back to `xml-diff`.

## Requirements

- Python 3 with `ncclient==0.6.19` and `lxml==5.2.2` (`requirements.txt`; the versions these
  services were tested with on the gateway).
- On the device: NETCONF enabled and port 830 reachable from the gateway. IOS XE:
  `netconf-yang`, plus `netconf-yang feature candidate-datastore` for candidate/commit.
- Inventory node attributes: `itential_host`, `itential_user`, `itential_password`, and
  optionally `itential_driver_options.netconf` (`port`, `timeout`, `lock_timeout`,
  `lock_poll_interval`).

## Import into IAG5

1. Put this code in your own repository.
2. In `import.yaml` set `url` to that repository and set `reference` to a release tag. The
   gateway pulls the repository on every service execution, so a branch reference would
   deploy every merge immediately.
3. Import, then check the services:
   ```bash
   iagctl db import import.yaml --repository netconf-python --force
   ```
4. Import adds and replaces by name but never deletes. List what the gateway has with
   `iagctl get services` and `iagctl get decorators`, and remove anything no longer in
   `import.yaml`. Delete the services first, then their decorators (delete does not check
   references), and check workflow bindings before deleting a service:
   ```bash
   iagctl delete service <name>
   iagctl delete decorator <name>
   ```
   Older iagctl versions take `iagctl delete service python-script <name>`.

Service names are stable. `main.py` still accepts the old internal op name
`netconf-send-command` for `netconf-send-config-xml`, so a gateway imported before the
rename keeps working.

## Run locally and test

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

NETCONF_OP=netconf-is-alive python main.py --host 192.0.2.1 --user admin --password "$PASS"
NETCONF_OP=netconf-preview-config python main.py --host 192.0.2.1 --user admin \
  --password "$PASS" --config_xml '<config>...</config>'

python3 -m unittest test_main      # offline, no device needed
```

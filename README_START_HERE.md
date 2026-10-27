# Medical Record Integrity System — Security Edition

Academic Flask prototype for demonstrating record integrity checks and incident handling. **Do not use real patient data or deploy publicly.**

## Features
- Doctor, Auditor, Admin roles with server-side route checks.
- SHA-256 record hash checks and a deterministic Merkle Root check.
- Authorized doctor edits create a new version and update the trusted root.
- Verification failures create a CRITICAL alert and lock the affected record.
- Edit routes reject locked records.
- Admin security dashboard lists alerts and locked records; admins can resolve alerts, unlock after investigation, and remove disposable `DEMOLOCK_` records.
- Safe copy-only tamper demo.
- Separate automatic-lock demo that creates a disposable `DEMOLOCK_...` record, simulates a direct data change while preserving its trusted hash, locks it, and alerts Admin. It does not modify the selected original patient record.
- Login failure tracking: five failures within five minutes trigger a five-minute account lock and alert.
- Audit trail for login attempts, record views, edits, verification, alerts, lock/unlock, and admin actions.
- CSRF tokens on state-changing forms; password hashes stored in SQLite.

## Run locally
Python 3.10+ recommended.

```bash
cd medical_verifier_app
python -m pip install -r requirements.txt
python app.py
```
Open `http://127.0.0.1:5000`.

## Run in Google Colab
1. Upload this ZIP into a new Colab notebook.
2. Run the launcher cell provided separately, or extract the ZIP and install `requirements.txt`.
3. Start `app.py` and open the Colab proxy URL for port 5000.

Demo accounts on a fresh database:
- Doctor: `doctor` / `doctor123`
- Auditor: `auditor` / `auditor123`
- Admin: `admin` / `admin123`

These are demonstration credentials. Change them before sharing the app. Existing databases retain their existing users/passwords.

## Demonstrate record locking
1. Log in as Doctor or Admin and open **Tamper Demo**.
2. Keep the default source record ID, e.g. `REC000011`.
3. Click **Run automatic lock demo (test record only)**.
4. The app creates a disposable `DEMOLOCK_...` record with a hash mismatch, creates a CRITICAL alert, and locks that test record.
5. Open **Admin → Security**. The test record should appear under Locked records.
6. Try opening `/edit/DEMOLOCK_...`; the server redirects away from the edit form because the record is locked.
7. As Admin, investigate and unlock if appropriate, or use **Delete demo record** to remove the disposable test record and its lock. The selected original record is not modified.
8. To show the actual verifier path, open the test record's **Verify** link before deleting it. The hash check should fail and the verifier will keep the test record locked.

## Important limitations
- Admin alerts are in-app database alerts, not email/SMS notifications.
- SQLite/CSV demo setup is not production healthcare security. A production system requires a security review, protected/off-host integrity checkpoints, backups, MFA, rate limiting, CSRF/session hardening, secure secret management, database permissions, privacy controls, and compliance review.
- The Merkle Root is stored in the same SQLite database in this academic prototype. An attacker with full database write access could modify both data and the root; production must protect/sign the trusted root separately.
- The included dataset is for demonstration. Do not enter real patient information.

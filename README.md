# COMPESA Event Intelligence Platform — Enhanced Build

A runnable FastAPI + SQLite + vanilla JS PWA-style event platform designed around the supplied COMPESA requirements and the provided visual reference.

## Run on Windows

1. Extract the ZIP.
2. Open PowerShell in the extracted `COMPESA` folder.
3. Run:

```powershell
cmd /c run.bat
```

4. Open `http://127.0.0.1:8000`.

`run.bat` creates `.venv`, installs requirements and starts FastAPI automatically.

## Account security

Login credentials are intentionally **not displayed anywhere in the public UI**. Passwords are never rendered, logged, or recoverable from the application. Use the existing local database for the included development accounts, or replace the database/seed credentials before production hosting.

## Gmail approval email

Copy `.env.example` to `.env` and edit the file with Notepad. **Do not paste `SMTP_HOST=...` lines directly into PowerShell.**

```powershell
Copy-Item .env.example .env
notepad .env
```

Set:

```env
SMTP_HOST=smtp.gmail.com
SMTP_PORT=587
SMTP_USER=yourgmail@gmail.com
SMTP_PASSWORD=your-google-app-password
SMTP_FROM=COMPESA Events <yourgmail@gmail.com>
```

Use a Google App Password, not your normal Gmail password. The project loads `.env` automatically.

## Core tested flow

Student registration → PENDING → Admin Registration Approvals → student branch/year/division/Gmail visible to authorized admin → Approve → registration becomes APPROVED → secure QR becomes active → personal portal notification → professional HTML approval email → email delivery log/audit.

## Student privacy boundary

The student API/UI intentionally does not expose event participant lists, participant counts, or the admin registration directory. Students see their own profile, own registrations, relevant events/venues, personal notifications, personal certificates, personal points/timeline, personalized recommendations and their own AI answers.

## Password

Passwords are never stored in plaintext and cannot be retrieved by the application. Login, registration and reset forms have a show/hide password control. Forgot-password creates a time-limited reset token; when SMTP is configured it is emailed to the student's notification Gmail. In local development, `COMPESA_DEV_RESET=true` (the default when no `.env` is present) shows the reset link directly on screen instead of emailing it.

### If you are locked out of the admin account

Three ways to reset any account's password, from easiest to most "break glass":

1. **In the app**: Admin login page → "Forgot password?". Works immediately in local development (`COMPESA_DEV_RESET=true` by default), or on any deployment where SMTP is configured.
2. **In the app, no email needed**: Admin login page → "Locked out?". This uses a secret `COMPESA_ADMIN_RECOVERY_KEY` you set once in `.env` (see `.env.example`). Enter the account email, your recovery key, and a new password. Disabled until you set that key.
3. **Directly on the database, no server/browser needed**: run `reset_admin_password.bat` (Windows, double-click) or `python3 reset_admin_password.py` (Mac/Linux/anywhere). It edits the database file directly and works even if the server isn't running and SMTP was never configured.

The default seeded accounts (change these before going live) are `admin@compesa.local`, `coordinator@compesa.local` and `student@compesa.local`, all with password `Compesa@123`.

## Security notes

- PBKDF2 password hashing.
- Signed short-lived session tokens.
- Role checks for admin/coordinator/volunteer actions.
- Secure random QR registration tokens.
- Duplicate registration prevention.
- Deadline and venue conflict validation.
- Audit logging for administrative changes.
- Certificate integrity hash + public verification endpoint.
- No arbitrary server-side code execution for coding submissions; demo judge intentionally uses deterministic safe scoring.

## Branding

The supplied screenshot was used as the visual reference. The included brand asset is used in the public hero, navigation, portals, emails and generated certificates.

## Production / Hosting

The application binds to `0.0.0.0` and supports a hosting `PORT` through the included `render.yaml`. Set these environment variables in your host: `COMPESA_SECRET`, `COMPESA_DEV_RESET=false`, `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASSWORD`, and `SMTP_FROM`. Never commit `.env` or real Gmail App Passwords.

For Render, connect the repository and use the included `render.yaml`. SQLite is suitable for a demo/single-instance deployment; for durable production data, use persistent storage or migrate the database layer to a managed database.

## Footer branding

Every public, authentication, student and admin screen includes: **Designed & Developed by @anis_sayyad01** with an Instagram icon linking to the supplied handle.

## Camera QR scanning
The admin QR Attendance screen uses the device camera with `getUserMedia` and sends camera frames to the FastAPI server for QR decoding with OpenCV. It does **not** depend on the browser's `BarcodeDetector` API. For deployed sites, use HTTPS and allow camera permission. `localhost` is also treated as a secure context by modern browsers.


## v7 additions
- Admin-editable Live Event Mode: SCHEDULED/LIVE/PAUSED/ENDED, live title, venue, timing, round/session, instructions and emergency updates.
- Registered students receive portal notifications for LIVE/emergency updates and can view live event details without seeing other participants.
- Smart Venue Manager: create/edit/remove venues, building/floor/room, capacity, facilities, address, Google Maps URL and coordinates, with event conflict protection.
- Admin CSV exports: registered students, attended students, event participants and all student records. Passwords are never exported.
- Volunteer CRUD: add/edit/remove, event assignment, position, shift, responsibilities and status.
- Paid event online registration: students can select Online Payment and see the supplied COMPESA payment QR, then save a payment reference.
- Payment mode/status/reference are stored per registration for admin review.

### Latest fixes
- Fixed a bug where uploading an event poster/banner image always failed with a server error (missing `uuid` import). Image uploads now work.
- Added a global error handler so an unexpected bug in one request returns a clean error message instead of a raw server crash.
- Added Admin → **Database**: one-click backup download and restore, plus an automatic snapshot on every server boot — see "Database persistence on Render" below for why this matters on free hosting.
- Added a no-email admin account recovery path (`COMPESA_ADMIN_RECOVERY_KEY` + the "Locked out?" link, or `reset_admin_password.py` / `.bat`) for when you're locked out and SMTP isn't set up.
- The PWA service worker now checks the live server first and only falls back to its offline cache on failure, so a bugfix or redeploy is no longer hidden behind an old cached copy in people's browsers.
- Admin can edit current event registration fees directly from **Payments → Current event fees**.
- CSV report downloads now use the authenticated admin session, so the browser no longer opens `/api/reports/*.csv` without the Bearer token.
- The student **Skill & Portfolio** navigation/page has been removed. Profile skills data remains available for event matching.
- Volunteer positions are limited to **President, Vice President, Secretary, Treasurer, Coordinator**.
- Render configuration remains included in `render.yaml`.

## Database persistence on Render (why data "resets")

This application uses SQLite, a single file on disk (`data/compesa.db`). **Render's free web service plan does not keep that disk** — it is wiped on every redeploy, and can also be reset when the free instance spins down and back up. This is a hosting-plan limitation, not an application bug: the same database file is durable and stable when it sits on normal storage (your own PC, a VPS, or a paid Render disk).

Three ways to deal with it, depending on how much you want to spend:

1. **Free, built-in safety net (already set up for you)**: as a `super_admin`, open **Database** in the admin sidebar. **Download backup** saves the entire database as one file to your computer; **Restore from backup** uploads it back in one click. Download a backup before you expect a redeploy or a long idle period, and restore it afterwards. The app also auto-snapshots the database into `data/backups/` every time it boots, which protects against an admin mistake (but not against the host wiping the whole disk, since that folder is wiped too).
2. **Paid, fully automatic**: attach a Render persistent disk and set `COMPESA_DB_PATH=/var/data/compesa.db` (or another file under the disk mount) in your environment variables. Data then survives redeploys with no manual steps, and the backup/restore feature above still works as extra insurance.
3. **Free, more work**: migrate from SQLite to a managed free Postgres database (e.g. Render's own Postgres, Neon or Supabase). This needs code changes to the database layer and is a bigger job than options 1–2.

For local use (`run.bat` / `python3 app.py` style via uvicorn) this does not apply at all — the database file lives permanently on your own computer.

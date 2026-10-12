# BrandShield AI

BrandShield is a full-stack brand-monitoring service. It combines live
reputation lookups with public search and app-store catalog results. Each
account has private monitored brands, scan history, and findings.

## What a scan checks

- **Google Web Risk:** looks up the HTTPS homepage of an optional official
  domain in Google's threat lists. The non-commercial Safe Browsing API is not used. Web Risk receives the checked URL.
- **VirusTotal:** reads an existing domain report; it does not submit URLs for
  scanning. VirusTotal receives the domain lookup.
- **Brave Search:** searches public results for social-profile candidates and
  Google Play listings. Brand names are sent as search queries. Results are
  unverified leads, not evidence that an account or app is fake. Brave Search
  is usage-priced; review the current plan and add spending controls.
- **Apple App Store Search:** searches Apple's public software catalog. Apple receives the brand-name query. Results are retained only when the brand name appears in the listing title or publisher; the publisher is shown for manual comparison. These are unverified catalog matches, not proof of impersonation.

Google Play does not provide a public third-party app-catalog search API in its
official Developer API. BrandShield uses Brave search results for Google Play
listing discovery, not undocumented scraping or the publisher-only Developer
API.

Provider coverage can be incomplete or delayed. An empty result is not a
clean/safe verdict. Verify evidence with the source and investigate findings
manually before taking action.

The homepage supports one-time scans without an account. These scans require
consent to share the submitted brand name and optional domain with the listed
providers, are limited to five requests per hour per IP address, and are not
saved to scan history. Sign in to save scans and manage monitored brands.

## Run locally

Requirements: Python 3.12+ and a modern browser.

1. From the repository root, prepare a backend environment:

   ```powershell
   cd backend
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   Copy-Item .env.example .env
   ```

2. Generate a secret with `python -c "import secrets; print(secrets.token_urlsafe(48))"`.
   Put its output in `backend/.env` as `JWT_SECRET_KEY=...`. Add provider API
   keys there if you have them. Never commit `.env` or paste secrets into
   issues, source code, or chat.

3. Start the application from `backend`:

   ```powershell
   python -m uvicorn main:app --reload --port 8000 --env-file .env
   ```

   Open <http://127.0.0.1:8000>. The FastAPI docs are at
   <http://127.0.0.1:8000/docs>. The API also serves the frontend, so do not
   open the HTML with `file://` or use a separate static server.

The default database is local SQLite. The app creates its tables on first
start. Existing prototype tables are left untouched.

## Deploy to Render + Neon

1. Create a PostgreSQL database in Neon and copy its pooled connection string.
   Create a Render Web Service from this GitHub repository on the `main`
   branch. Configure the service with:
   - Root directory: `backend`
   - Build command: `pip install -r requirements.txt`
   - Start command: `python -m uvicorn main:app --host 0.0.0.0 --port $PORT`
   - Instance type: Free (subject to Render's current free-tier limits)

2. Set these variables in the Render service environment:
   - `APP_ENV=production`
   - `DATABASE_URL` to the Neon PostgreSQL connection string
   - `JWT_SECRET_KEY` to a unique, randomly generated secret of at least 32
     characters
   - `GOOGLE_WEBRISK_API_KEY`
   - `VIRUSTOTAL_API_KEY`
   - `BRAVE_SEARCH_API_KEY`
   - `SCHEDULE_POLL_SECONDS=60`
   - `SCHEDULE_BATCH_SIZE=3`

   `ALLOWED_ORIGINS` may be left unset when the frontend is served by this
   same-origin app. Never put provider keys in frontend JavaScript or GitHub.
   Keep the service to one running replica while using the in-process login and
   registration rate limiter.

3. Deploy and check `/health`. Register a test account, then verify each
   provider status and a scan before sharing the deployment. Because the Render
   root directory is `backend`, frontend-only changes outside that directory
   may require a manual deploy from the Render dashboard.

Provider accounts may require billing, API enablement, and key restrictions.
Brave requests are usage-priced; scheduled checks are opt-in and start no more
often than once every 24 hours per brand. On Render's free tier, the service can
sleep while idle; its in-process scheduled worker cannot run while the service
is stopped, so scheduled scans are not guaranteed during sleep. Set provider
budget alerts. Hosting and provider usage are separate costs.

## Privacy and account limitations

Before each on-demand scan or when adding a monitored brand, the user must
consent to external lookups. The app sends the brand name to Brave and Apple;
when a domain is supplied, Google Web Risk receives its HTTPS homepage URL and
VirusTotal receives a domain-report request. Google Search receives the submitted name only if the user follows a Google Search link. Google determines which results are shown; BrandShield cannot guarantee every indexed result. No URLs are submitted to
VirusTotal for scanning. Scheduled scans repeat the consented lookups.

Passwords are Argon2-hashed, and sessions use signed HttpOnly cookies. The
service has basic per-IP rate limits for account creation and sign-in. Email
verification, password reset, multi-factor authentication, account deletion,
shared/distributed rate limiting, and production backup/retention operations
are not yet implemented. Review provider terms, privacy requirements, quotas,
and applicable laws before operating this as a public commercial service.

## Development checks

Install optional test dependencies with `python -m pip install -r
requirements-dev.txt` from `backend`, then run `python -m pytest` from the
repository root.

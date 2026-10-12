# BrandShield AI

BrandShield AI is a full-stack brand-protection demo built with static HTML,
CSS, and JavaScript, plus a Python FastAPI backend and SQLite database.

> **Demo only:** analysis and findings are simulated. Authentication is not
> implemented, and the app does not scan real websites, social platforms, or
> mobile applications. Do not use it for security decisions or real customer
> data.

## Features

- Submit a brand name for a clearly labeled mock analysis.
- Add and remove monitored brands in a local SQLite database.
- Create simulated findings and update their status.
- View summary reports and download report data as JSON.

## Requirements

- Python 3.10 or newer
- A modern web browser
- VS Code Live Server, or another local static web server

## Run locally

1. Start the API from the `backend` directory:

   ```powershell
   cd backend
   python -m venv .venv
   .venv\Scripts\Activate.ps1
   python -m pip install -r requirements.txt
   python -m uvicorn main:app --reload --port 8000
   ```

   The API is available at <http://127.0.0.1:8000>; its interactive
   documentation is at <http://127.0.0.1:8000/docs>.

2. Serve the `frontend` directory using VS Code Live Server, or another local
   static server. The API allows the default local origins on ports 5500 and
   5501. Open the server's `index.html` page.

The frontend API URL is configured in `frontend/js/api.js`. The SQLite
database is created locally as `backend/brandshield.db`.

## Current limitations

- Sign-in and registration forms are placeholders; no accounts are created.
- Analysis and demo findings are mock data, not detections.
- Data is stored in a local SQLite database without user isolation.
- The frontend API URL and CORS origins are configured for local development.
- This project has not been configured or tested for production deployment.

Before using it as a hosted service, implement and test authentication,
authorization, production data storage, deployment-specific API/CORS settings,
backups, and a data-retention policy.

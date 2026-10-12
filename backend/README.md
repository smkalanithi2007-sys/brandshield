# BrandShield AI

A full-stack brand protection prototype.

## Technology
- HTML, CSS, JavaScript
- Python and FastAPI
- SQLite

## Project structure
- frontend/: website pages and assets
- backend/: API and local database

## Install backend

Open a terminal in the backend folder.

Create a virtual environment:

    python -m venv .venv

Activate it on Windows:

    .venv\Scripts\activate

Or on macOS/Linux:

    source .venv/bin/activate

Install packages:

    python -m pip install -r requirements.txt

Start the API:

    python -m uvicorn main:app --reload --port 8000

API documentation:

    http://127.0.0.1:8000/docs

## Run frontend

Open the frontend folder in VS Code.
Right-click index.html and select Open with Live Server.

The expected local address is:

    http://127.0.0.1:5500

## Important

Threat analysis uses simulated data only.
Authentication is not implemented.
Do not use this prototype for real security decisions.
Do not expose the development server publicly.
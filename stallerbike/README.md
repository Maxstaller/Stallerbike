# Stallerbike Software - Inventory Dashboard (Flask)

## Übersicht
Dies ist ein fertig konfiguriertes Inventory-Management-System für Fahrräder. 
Es läuft mit Flask (Python) und einer SQLite/Postgres-Datenbank.

Features:
- Mehrere Benutzer (Admin / Mitarbeiter)
- Admin kann Benutzer anlegen/löschen, Rollen vergeben
- Bikes verwalten: Kategorie, Zustand, Standort, Notizen
- Suche & Filter, einfache UI (Bootstrap)

## Schneller Start (lokal)
1. Python 3.10+ installieren.
2. ZIP entpacken und Verzeichnis öffnen:
   ```bash
   unzip stallerbike.zip
   cd stallerbike_backend
   ```
3. Virtuelle Umgebung und Abhängigkeiten:
   ```bash
   python -m venv .venv
   source .venv/bin/activate   # Linux/macOS
   .venv\Scripts\activate    # Windows (PowerShell: .venv\Scripts\Activate.ps1)
   pip install -r requirements.txt
   ```
4. Datenbank initialisieren und Admin-Benutzer anlegen (ersetze adminpass):
   ```bash
   flask --app app init-db
   flask --app app create-user --username admin --password adminpass --admin
   ```
5. Starten:
   ```bash
   flask --app app run
   ```
6. Öffne im Browser: http://127.0.0.1:5000
   Login: admin / adminpass

## Deployment (empfohlen: Render.com)
Für ein dauerhaft erreichbares Online-Dashboard empfehle ich Render.com oder Railway.

Kurz (Render):
- Lege ein neues GitHub-Repo an und pushe den Ordner `stallerbike_backend`.
- Erstelle ein neues Web Service in Render, Point auf das Repo, Build Command: `pip install -r requirements.txt`, Start Command: `gunicorn app:app`.
- Wähle eine Datenbank (Postgres) und setze die Umgebungsvariable `DATABASE_URL` in Render (Postgres-Verbindungs-URL).
- Optional: Setze `FLASK_ENV=production` und `SECRET_KEY` in Render Environment variables.

Hinweis: SQLite ist für Tests lokal ok, für Hosting im Internet solltest du Postgres verwenden (DATABASE_URL).

## Support
Wenn du möchtest, übernehme ich das Deployment-Schritt-für-Schritt — sag mir, ob du ein Render-Account hast oder ich dir eine Anleitung per Screenshots geben soll.

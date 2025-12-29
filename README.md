# Contact API (Node/Express)
Simple email API for the web application pentest contact form. Deploy on Heroku; frontend on Vercel will POST here.

## Setup
1) Copy env file
```
cp .env.example .env
```
2) Fill SMTP creds in `.env` (host, port, user, pass, FROM_EMAIL, TO_EMAIL).
3) Set `ALLOWED_ORIGINS` to your Vercel domain(s), comma-separated.
4) Install deps
```
npm install
```
5) Run locally
```
npm run dev
```
API runs at http://localhost:3001

## Endpoints
- `POST /contact`
  - Body JSON: `{ name, email, url, message? }`
  - Validates fields, rate-limited, CORS restricted
  - Sends email via your SMTP
- `GET /health` (ping)

## Deploy to Heroku
```
heroku create your-contact-api
heroku config:set SMTP_HOST=... SMTP_PORT=587 SMTP_USER=... SMTP_PASS=... FROM_EMAIL=... TO_EMAIL=... ALLOWED_ORIGINS=https://your-vercel-site.vercel.app
heroku config:set RATE_LIMIT_WINDOW_MS=900000 RATE_LIMIT_MAX=100
heroku config:set PORT=3001
heroku git:remote -a your-contact-api
# commit your changes if needed
heroku push origin main
```
Procfile is included (`web: node server.js`).

## Frontend wiring (Vercel)
Point your contact form to POST `https://your-contact-api.herokuapp.com/contact` with JSON body `{ name, email, url, message }`.

## Notes
- Keep `.env` out of git (.gitignore included)
- This API assumes a reliable SMTP provider (e.g., SendGrid, Mailgun, Postmark). Use their SMTP creds.
- If you want HTTPS locally, run behind a proxy (ngrok) or use Heroku staging.

# Fakka License Server

Backend + SQLite database + Admin Web UI for license keys.

## 1) Requirements
Node.js 20+ recommended.

## 2) Install
```bash
npm install
cp .env.example .env
```

Edit `.env` and set a strong `JWT_SECRET` and `ADMIN_PASSWORD`.

## 3) Run
```bash
npm start
```

Open:
`http://localhost:3000`

## API

### Validate from the Android app
`POST /api/license/validate`

```json
{
  "key": "F-1234",
  "device_id": "optional-device-id"
}
```

Success:
```json
{
  "valid": true,
  "type": "admin",
  "expires_at": null,
  "remaining_uses": 0
}
```

### Admin
Login: `POST /api/auth/login`

Create: `POST /api/admin/licenses`
List: `GET /api/admin/licenses`
Edit: `PATCH /api/admin/licenses/:id`
Delete: `DELETE /api/admin/licenses/:id`

## Production
Put the server behind HTTPS (Nginx/Caddy/Cloudflare), set NODE_ENV=production,
use a long random JWT_SECRET, and add rate limiting/WAF at the reverse proxy.
Do not put the admin password or JWT secret in the Android APK.

## First admin key
After starting the server, create `F-1234` from the admin panel as type `admin`.

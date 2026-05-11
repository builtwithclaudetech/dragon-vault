# Placeholders — Dragon Vault

This file documents every placeholder value used in the source code. Replace each
placeholder with your own values before building and deploying.

## Placeholder Reference

| Placeholder | Where Used | What to Replace With |
|---|---|---|
| `YOUR-SERVER-IP` | deploy scripts, nginx config, docs | Your VPS public IPv4 address |
| `YOUR-OLD-SERVER-IP` | docs/handoff.md | Previous server IP (historical reference only) |
| `pwm.example.com` | nginx config, certbot scripts, source comments, tests | Your actual domain name |
| `user@example.com` | appsettings.json, GoogleAuthOptions.cs, tests, docs | Your Google account email for OAuth allowlist |
| `CHANGE_ME` | setup-directories.sh, appsettings.Development.json | Your SQL Server SA password |
| `YOUR-USERNAME` | deploy service files, install scripts | Your Linux username for running the backup service |
| `builtwithclaudetech` | service unit docs URL, deploy scripts | Your GitHub organization or username |
| `the maintainer` | source code comments | Your name (for code ownership clarity) |
| `a prior project` | source code comments | N/A (architectural reasoning — can leave as-is or replace) |

## Required Configuration Files

These files are NOT in the repository (`.gitignore`'d). You must create them:

1. **`src/PasswordManager.Web/appsettings.Development.json`**
   ```json
   {
     "ConnectionStrings": {
       "DragonVault": "Server=localhost;Database=DragonVault;User Id=sa;Password=YOUR_SQL_PASSWORD;TrustServerCertificate=True;Encrypt=True"
     },
     "Authentication": {
       "Google": {
         "ClientId": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
         "ClientSecret": "YOUR_GOOGLE_CLIENT_SECRET"
       }
     }
   }
   ```

2. **`/var/opt/dragonvault/appsettings.Production.json`** (on your server, outside the repo)
   ```json
   {
     "ConnectionStrings": {
       "DragonVault": "Server=127.0.0.1,1433;Database=DragonVault;User Id=sa;Password=YOUR_SQL_PASSWORD;TrustServerCertificate=True;Encrypt=True"
     },
     "Authentication": {
       "Google": {
         "ClientId": "YOUR_GOOGLE_CLIENT_ID.apps.googleusercontent.com",
         "ClientSecret": "YOUR_GOOGLE_CLIENT_SECRET",
         "AllowedEmails": ["your-email@gmail.com"]
       }
     },
     "WebAuthn": {
       "RpId": "your-domain.com",
       "RpName": "Dragon Vault",
       "Origins": ["https://your-domain.com"],
       "ChallengeTtlSeconds": 300
     }
   }
   ```

3. **`/var/opt/dragonvault/.env`** (on your server)
   ```
   SQL_PASSWORD=YOUR_SQL_PASSWORD
   # GDRIVE_BACKUP_TARGET=gdrive:/dragonvault-backups
   ```

## Google OAuth Setup

1. Go to https://console.cloud.google.com/apis/credentials
2. Create a project → OAuth consent screen (External)
3. Create OAuth 2.0 Client ID (Web application)
4. Add authorized redirect URI: `https://your-domain.com/signin-google`
5. Copy the Client ID and Client Secret to your config files

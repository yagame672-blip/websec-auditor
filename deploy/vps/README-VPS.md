# Websec-Auditor sa iyong sariling VPS (websec-audit.site)

Pinasimple nitong gabay ang deployment ng iyong websec-auditor app mula sa Vercel
papunta sa iyong Namecheap VPS.

## Ano ang kailangan mo bago magsimula

1. **VPS details mula sa Namecheap** (makikita sa Namecheap panel → ang VPS mo):
   - **IP address** ng VPS (hal. `168.100.1.50`)
   - **Root password** (password para mag-login) — madalas nasa panel o sa welcome email
   - Ang **OS** na naka-install (hal. Ubuntu 22.04) — pwede ring ipalit sa panel kung gusto
2. **Ang domain** `websec-audit.site` (binili mo sa Namecheap)
3. Windows 10/11 (may built-in na `ssh`, `scp`, at `tar`)

> Hindi mo kailangan ng kaalaman sa Linux — karamihan ay automated.

---

## HAKBANG 1: Kunin ang VPS details

Sa iyong Namecheap account:
- Pumunta sa **Namecheap dashboard** → hanapin ang iyong **VPS** (baka naka-label na "VPS" o "Private Server")
- I-click ito para makita ang **IP address** at **Root Password**
- Kung wala kang nakikitang password, i-click ang **"Access Details"** o **"Password"** button

Isulat mo ito — kailangan natin mamaya:
- `VPS IP:`
- `Root password:`
- `OS:`

---

## HAKBANG 2: Ituro ang domain papunta sa VPS (DNS)

Para mapuntahan ng `websec-audit.site` ang iyong VPS, kailangan ng **A record**.

1. Sa Namecheap dashboard, hanapin ang **Domain List** → i-click ang **Manage** katabi ng `websec-audit.site`
2. Hanapin ang section na **Advanced DNS** (o **Nameservers**)
3. Siguraduhing naka-`BasicDNS` ang nameservers (hindi "Namecheap PremiumDNS" o custom) — kung iba, i-click ang i-edit at piliin ang **Namecheap BasicDNS**
4. Sa **Host Records**, idagdag (i-click ang **Add New Record**):
   | Type | Host | Value | TTL |
   |------|------|-------|-----|
   | A | `@` | `<iyong-VPS-IP>` | Automatic |
   | A | `www` | `<iyong-VPS-IP>` | Automatic |
5. I-click ang **Save All Changes**

> Ang DNS ay kumakalat nang 5 minuto hanggang 24 oras. Hindi hadlang ito — pwede mong simulan
> ang HAKBANG 3 habang kumakalat.

---

## HAKBANG 3: I-deploy (isang command)

Sa Windows, buksan ang **PowerShell** at i-type (palitan ang mga value):

```powershell
powershell -ExecutionPolicy Bypass -File D:\websec-auditor\deploy\vps\deploy.ps1 `
    -VpsIp "168.100.1.50" `
    -SshUser root `
    -Domain websec-audit.site `
    -Email "you@example.com"
```

Magsasagawa ito ng:
1. Pag-package ng app (awtomatiko — inaalis nito ang Vercel-only files)
2. Pag-upload sa iyong VPS
3. Pag-install ng Python, nginx, TLS certificate (libre, Let's Encrypt)
4. Pag-setup ng app bilang serbisyo (auto-restart)
5. Pagbukas ng firewall (22, 80, 443)

**Hihingi ito ng password** (ang Root password mo) ng 2–3 beses — i-type mo lang.

> Kung may SSH key ka na, hindi mo na kailangan mag-type ng password nang paulit-ulit.

---

## HAKBANG 4: I-verify

Pagkatapos ng deploy (at nag-kalat na ang DNS), buksan sa browser:

```
https://websec-audit.site
```

Dapat makita mo ang scanner UI. I-scan mo ito para i-test:
- Target: `http://127.0.0.1:8099` (demo server) — o i-scan ang `https://websec-audit.site` mismo
- Dapat magpakita ito ng mga findings tulad ng dati sa Vercel

Mga useful command (sa VPS, via `ssh root@<IP>`):
- `systemctl status websec-auditor` — tingnan kung tumatakbo ang app
- `journalctl -u websec-auditor -e` — logs
- `sudo certbot renew --dry-run` — i-test ang certificate renewal

---

## Pag-rollback (kung kailangan)

Kung may mali, ang Vercel version mo ay buhay pa:
```
https://websec-auditor.vercel.app
```
Kaya walang mawawala. Sabihin mo lang sa akin kung may problema.

---

## Paalala sa seguridad

- Ang VPS ay publiko — **huwag ilagay ang root password kahit saan**
- Binabantayan ang `/scan` (rate limit) pero bukas pa rin ito sa publiko — i-scan mo lang
  ang mga site na **pagmamay-ari mo o pinayagan ka** (parehong paalala ng app mismo)
- Ang `websec-audit.site` ay iyo — kung gusto mo ng mas magandang pangalan, sabihin mo lang


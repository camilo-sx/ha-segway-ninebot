# API cloud internacional (Segway Mobility) — hosts y rutas

Extraído estáticamente de `com.ninebot.segway` v5.4.2 (APK Aptoide, SHA256
20d6d086…915a), `classes.dex` sin empaquetar. Solo-lectura del fichero local.

## Región

`assets/region.json` mapea país → región (`R`). **Colombia (`CO`, +57) → `ore`**
(AWS Oregon / us-west-2). Otras: `bj` China, `sg` Singapur, `fra` Fráncfort,
`ore` Américas. La cuenta de Camilo resuelve a **`ore`**, no a los `*-bj` del
cliente chino de ninebot-recon.

## Plantillas de host (`%s` = región)

| Plantilla en el dex | Para `ore` |
|---|---|
| `passportapi-%s.ninebot.com` | `passportapi-ore.ninebot.com` |
| `api5-%s.ninebot.com` | `api5-ore.ninebot.com` |
| `api5-h5-app-%s.ninebot.com` | `api5-h5-app-ore.ninebot.com` |

Hosts "overseas" sin región (compartidos): `os-eb.ninebot.com` (ebike overseas),
`os-st.ninebot.com` (steeldust overseas), `ebike.ninebot.com`, `steeldust.ninebot.com`.
Business visto solo como `api-jhcx-fra.ninebot.com` (sin variante `ore` en strings;
quizá EU-only o plantilla `api-jhcx-%s`).

## Diferencias con el cliente chino (ninebot-recon)

- Login: el dex intl muestra `/v3/user/login`, `/ninebot/account/login` y
  `/ninebot/accountoverseasbiz/login`. El cliente chino usa `/v6/user/login` en
  `api-passport-bj`. **El contrato de login internacional difiere** (host, ruta y
  posiblemente la firma) → el cliente vendorizado NO logueará intl sin adaptar.
- Lista de vehículos: intl `/binding/my-vehicle` (chino `/vehicle/binding/my-vehicle`).

## Superficie de credencial BLE (a sondear)

Rutas candidatas halladas: `/vehicle/auth`, `/vehicle-auth/check`,
`/vehicle-auth/check-bind`, `/vehicle-auth/get-code`, `/common-user/common-vehicle-info`,
`/vehicle/confirm_nfc_secret`. Probablemente devuelven el **ident** / material de
auth por vehículo. Pendiente confirmar si alguna devuelve la **contraseña de
sesión** (16 B) o solo el ident.

## Lectura de arquitectura (apk-re, confianza media-alta, sin confirmar en dex)

Libs nativas `libnesec.so` / `libnbcrypto.so` hacen la derivación de clave BLE
**en el dispositivo**. La contraseña de sesión `{serie}_decrypt` sería el
RESULTADO cacheado del handshake, no un valor descargado de la nube. Implicación:
la nube da el ident, no la contraseña.

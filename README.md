# qrauth

Divide el QR de export de Google Authenticator (`otpauth-migration://offline?data=...`)
en N códigos QR para importar las cuentas en otra app de autenticación.

Google exporta las cuentas como uno o varios QR de migración. Esta herramienta
los decodifica y genera:

- **un QR `otpauth://` por cuenta**, que importa cualquier app (Aegis, 2FAS,
  Ente Auth, Bitwarden, 1Password, etc.);
- **N QR en el formato de Google** (`otpauth-migration://`), con los campos
  `batch_size`, `batch_index` y `batch_id` correctos, para apps que solo
  aceptan ese formato;
- un **índice HTML** para escanear los QR desde la pantalla;
- un **manifiesto JSON** con las cuentas decodificadas.

Todo corre localmente: la herramienta no sube ni envía nada.

## Requisitos

- Python 3.10 o posterior;
- `zbarimg` (paquete `zbar`) para leer los QR;
- `qrencode` para generarlos.

```sh
# Arch
sudo pacman -S zbar qrencode

# Debian / Ubuntu
sudo apt install zbar-tools qrencode
```

## Uso

```sh
./qrauth.py export.png
```

Se pueden pasar todos los lotes del export a la vez, como imágenes o como el
código `otpauth-migration://` en un archivo `.txt`:

```sh
./qrauth.py export-1.png export-2.txt -o out --chunks 2
```

Si el export original venía partido en varios QR, hay que pasar todos los
lotes; si falta alguno, la herramienta lo avisa.

### Opciones

| Opción | Descripción |
| --- | --- |
| `-o, --out DIR` | Carpeta de salida (por defecto `out`). |
| `--chunks N` | Además de un QR por cuenta, genera N lotes en formato Google. |
| `--dedupe` | Omite cuentas repetidas (mismo secreto, emisor y nombre). |
| `--list` | Solo lista las cuentas, sin generar imágenes. |

## Salida

```
out/
├── accounts/       un QR otpauth:// por cuenta
├── migration/      N lotes otpauth-migration://
├── index.html      índice visual con todos los QR
└── accounts.json   datos decodificados, incluidos los secretos
```

Abrí `out/index.html` en el navegador y escaneá los QR con la app destino.

## Seguridad

`out/` e `inputs/` contienen secretos TOTP. Tratalos como contraseñas y
borralos cuando termines de importar. El `.gitignore` del repo excluye esas
carpetas para que no se suban por accidente.

## Limitaciones

- Google parte los exports en lotes de 10 cuentas; la herramienta no puede
  recuperar un lote que no se le pasa.
- El QR de migración no incluye el período (`period`); en los QR `otpauth://`
  se asume el estándar de 30 segundos.

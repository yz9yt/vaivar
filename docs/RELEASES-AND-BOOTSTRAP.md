# Releases, bootstrap y despliegue sin Internet

El despliegue recomendado tiene tres piezas separadas:

- `./install.sh` instala únicamente Central en la máquina del operador y
  pregunta el puerto del panel.
- `./honeypot-install.sh` es el flujo interactivo para un honeypot remoto y
  pregunta sus puertos público y de control.
- `scripts/publish-release.sh` construye una imagen versionada y la empaqueta junto con `docker-compose.yml`.
- Central conserva el catálogo de releases aprobados y sirve el bundle al instalador.
- `scripts/honeypot-install.sh` descarga el bundle, comprueba su SHA-256 y carga la imagen localmente. Después muestra el resumen para dar de alta el honeypot en Central.

El puerto de control usa HTTP como transporte para no exigir certificados ni
paquetes TLS en cada VPS. Los mensajes de control no se envían en claro:
Central y el honeypot derivan una clave AES-256-GCM a partir del barriertoken
generado durante el deploy. Cada petición y respuesta viaja dentro de un
sobre cifrado; el token nunca aparece en una cabecera HTTP. Un mensaje
capturado o modificado no se puede leer ni aceptar sin esa clave. `legacy` se
mantiene únicamente para nodos antiguos que todavía usan el API HTTP con
Bearer en claro.

GitHub puede publicar el mismo bundle como alternativa para hosts con salida a Internet. No se usa `latest` para actualizar un nodo.

## 1. Publicar una release

En la máquina de CI o del operador:

```bash
scripts/publish-release.sh 1.0.1 /srv/vaivar/releases
```

El comando genera:

```text
vaivar-1.0.1.bundle.tar.gz
release-1.0.1.manifest.json
```

El bundle contiene la imagen Docker exportada y el compose de cliente apuntando a `vaivar:1.0.1`. El manifiesto contiene tamaño, versión y SHA-256. Se publica el artefacto antes que el manifiesto para que Central nunca seleccione una copia incompleta.

En la central, configura en `.env.central`:

```dotenv
VAIVAR_RELEASE_HOST_DIR=/srv/vaivar/releases
VAIVAR_RELEASE_DIR=/data/vaivar-central/releases
```

Monta esa configuración con `docker-compose.central.yml`. Después de copiar una nueva pareja de ficheros a `/srv/vaivar/releases`, Central la detecta en la siguiente petición; no hace falta reiniciar.

## 2. Emitir una capacidad temporal

Solo un administrador puede emitirla. La capacidad dura 15 minutos por defecto, sirve para descargar el instalador y el bundle, y se consume al completar el registro:

```bash
CENTRAL=http://central.example:8080
BOOTSTRAP_TOKEN=$(curl -fsS \
  -H "Authorization: Bearer $VAIVAR_CENTRAL_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"ttl_seconds":900}' \
  "$CENTRAL/api/v1/bootstrap/tokens" | jq -r .bootstrap_token)
```

El token no sustituye al token de administrador y no se acepta como `Authorization: Bearer`.

## 3. Host sin Internet: instalador servido por Central

Desde el host que alojará el honeypot, ejecuta como root. Sustituye las
variables por los valores elegidos para esa instalación; no hay ninguna IP o
puerto de una máquina concreta en el instalador:

```bash
HONEYPOT_HOST='<dirección accesible desde Central>'
PUBLIC_PORT='<puerto público elegido>'
CONTROL_PORT='<puerto de control elegido>'
PROFILE='<all|http|wiki|openapi|mcp>'

curl -fsSL \
  -H "X-Vaivar-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  "$CENTRAL/api/v1/bootstrap/installer" \
| sudo bash -s -- \
    --central "$CENTRAL" \
    --bootstrap-token "$BOOTSTRAP_TOKEN" \
    --host "$HONEYPOT_HOST" \
    --public-port "$PUBLIC_PORT" \
    --api-port "$CONTROL_PORT" \
    --profile "$PROFILE" \
    --control-channel encrypted
```

Antes de descargar o sustituir la instalación, el instalador comprueba que el puerto público y el puerto de control estén libres. Si los dos pertenecen al mismo proyecto Compose, los permite para que una actualización pueda reutilizarlos; cualquier otro proceso o honeypot provoca un error claro y no se inicia.

El instalador preserva el `site_id`, `VAIVAR_MASTER_SECRET`,
`VAIVAR_API_TOKEN` y `VAIVAR_COMPOSE_PROJECT` si ya existe `/opt/vaivar/.env`.
Por ello una actualización no crea una identidad nueva, no cambia credenciales
ni rompe la clave del canal. Para el primer despliegue genera credenciales
locales con permisos 600 y muestra un resumen con puerto público, puerto de
control HTTP, canal cifrado y token.

Si el `.env` se quedó desfasado respecto al contenedor que está ejecutándose,
una actualización del mismo proyecto Compose toma las credenciales y la
identidad del contenedor existente antes de escribir el nuevo `.env`; así no
rota accidentalmente el token operativo.

Con una Central HTTP no envía ese token por la red: el alta se hace
manualmente en la consola. El registro automático (`--register`) solo se
habilita al usar una URL HTTPS de Central.

En la consola, el alta manual necesita exactamente estos datos del resumen:

- dominio o IP del honeypot;
- puerto de comunicación/control;
- transporte HTTP;
- canal `encrypted`;
- token de barrera.

Al pulsar **Probar conexión**, Central envía una petición RPC cifrada a
`/api/secure/rpc`, comprueba el token y verifica que la identidad anuncia el
canal cifrado, el mismo `site_id` y los puertos públicos/control. Solo después
permite guardar el honeypot.

### Varios honeypots en el mismo host

Sí, se pueden ejecutar varios. Cada instancia que comparta servidor debe tener:

- un `--public-port` distinto;
- un `--api-port` distinto;
- un `--project-name` distinto;
- un `--install-dir` distinto;
- un `--site-id` distinto para que Central las identifique de forma independiente.

Ejemplo para una segunda instancia en el mismo host:

```bash
INSTALL_DIR_2='<directorio de la segunda instancia>'
PROJECT_2='<proyecto Compose de la segunda instancia>'
SITE_ID_2='<site_id de la segunda instancia>'
PUBLIC_PORT_2='<puerto público de la segunda instancia>'
CONTROL_PORT_2='<puerto de control de la segunda instancia>'
PROFILE_2='<perfil de la segunda instancia>'

curl -fsSL \
  -H "X-Vaivar-Bootstrap-Token: $BOOTSTRAP_TOKEN" \
  "$CENTRAL/api/v1/bootstrap/installer" \
| sudo bash -s -- \
    --central "$CENTRAL" \
    --bootstrap-token "$BOOTSTRAP_TOKEN" \
    --install-dir "$INSTALL_DIR_2" \
    --project-name "$PROJECT_2" \
    --site-id "$SITE_ID_2" \
    --host "$HONEYPOT_HOST" \
    --public-port "$PUBLIC_PORT_2" \
    --api-port "$CONTROL_PORT_2" \
    --profile "$PROFILE_2" \
    --control-channel encrypted
```

Los nombres de proyecto separan también los volúmenes de Docker (`vaivar-data` queda prefijado por el proyecto). En servidores diferentes sí se pueden repetir los mismos números de puerto, porque cada servidor tiene su propio espacio de red.

El host necesita Docker, Docker Compose, `curl`, `tar`, `gzip` y `sha256sum`. No necesita Git, Node ni acceso a Docker Hub: la imagen se carga desde el bundle.

## 4. Fallback GitHub con hash fijado

Si el host sí tiene Internet, se puede obtener el script desde GitHub y el bundle desde una release asset. El hash debe proceder de un canal confiable:

```bash
HONEYPOT_HOST='<dirección accesible desde Central>'
PUBLIC_PORT='<puerto público elegido>'
CONTROL_PORT='<puerto de control elegido>'
PROFILE='<all|http|wiki|openapi|mcp>'

curl -fsSL https://raw.githubusercontent.com/ORG/REPO/main/scripts/honeypot-install.sh \
| sudo bash -s -- \
    --artifact-url https://github.com/ORG/REPO/releases/download/v1.0.1/vaivar-1.0.1.bundle.tar.gz \
    --sha256 SHA256_DE_LA_RELEASE \
    --host "$HONEYPOT_HOST" \
    --public-port "$PUBLIC_PORT" \
    --api-port "$CONTROL_PORT" \
    --profile "$PROFILE" \
    --control-channel encrypted \
    --install-dir /opt/vaivar \
    --project-name vaivar
```

Este modo instala el nodo, pero no lo registra en Central porque no tiene una
capacidad de bootstrap. Se puede registrar después desde la consola con host,
puerto de API, transporte HTTP, canal `encrypted` y token.

## 5. Plantillas de contenido

El perfil (`wiki`, `http`, `openapi`, `mcp` o `all`) define la superficie técnica. La plantilla define el contenido visible: páginas, títulos, texto y enlaces locales. El nodo escapa todo el contenido y no ejecuta HTML, JavaScript ni URLs externas.

Central incluye plantillas iniciales. Desde el detalle de un honeypot, un administrador puede escoger una plantilla compatible y pulsar **Aplicar plantilla**. La misma operación está disponible por API:

```bash
curl -fsS -X POST \
  -H "Authorization: Bearer $VAIVAR_CENTRAL_ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"template_id":"wiki-default","version":1}' \
  "$CENTRAL/api/v1/nodes/SITE_ID/commands/apply_template"
```

Para publicar contenido propio se envía un documento `vaivar.template.v1` a `POST /api/v1/templates`. Hay que incrementar `version` cuando se cambia el contenido; así se conserva qué versión estaba activa en cada honeypot. El documento puede usar rutas como `/`, `/wiki/` y `/wiki/handbook`, pero no rutas de disco, `..`, scripts ni recursos externos.

## Modelo de seguridad

La instalación necesita permisos root para gestionar Docker y el volumen del nodo. El token de bootstrap es efímero, se almacena solo como hash en Central y se invalida después del alta. El bundle se acepta únicamente cuando su SHA-256 coincide con el manifiesto/asset esperado. El token de barrera se almacena cifrado en Central y además sirve como secreto compartido del canal AES-256-GCM; nunca se envía en claro al honeypot ni se manda al registro automático sobre HTTP. En producción, limita el puerto de control del honeypot a la red de Central. El HTTPS de la propia Central protege el acceso del navegador, los tokens de administración y, si se usa `--register`, el intercambio inicial de registro.

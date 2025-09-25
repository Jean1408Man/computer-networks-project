# Documentación del Proyecto L2 Messenger

Este proyecto tiene como objetivo crear una aplicación de mensajería a nivel de **Capa de Enlace (L2)** utilizando únicamente la **biblioteca estándar de Python**. La aplicación envía y recibe tramas Ethernet, implementando un protocolo personalizado en la capa L2.

## Objetivo

Desarrollar un sistema de mensajería en la red local basado en tramas Ethernet, utilizando un **EtherType** personalizado (0x88B5). El sistema permite el descubrimiento de nodos mediante **broadcast** y la comunicación entre ellos usando un protocolo definido sobre la capa de enlace.

---

## Estructura General

La aplicación está dividida en los siguientes módulos principales:

1. **Config**: carga la configuración desde un archivo `.toml`.
2. **RawSocket**: gestiona la creación de sockets **raw** para enviar y recibir tramas Ethernet.
3. **Protocolo L2MG**: define el encabezado y el formato de las tramas personalizadas (L2MG).
4. **Discovery**: gestiona el descubrimiento de nodos a través de **HELLO**/`HELLO_ACK` y la creación de una tabla de peers.
5. **CLI**: interfaz de línea de comandos para interactuar con el sistema (escuchar, descubrir, listar peers).

---

## Implementación

### 1. Carga de Configuración

Usamos un archivo **`app.toml`** para configurar el **EtherType**, la interfaz de red (`iface`), y el nombre del nodo. El archivo tiene el siguiente formato:

```toml
[app]
ether_type = "0x88B5"   # EtherType personalizado
iface = "auto"          # Interfaz de red (auto selecciona una válida)
node_name = "nodo-demo"  # Nombre del nodo
mtu_safe = 1400          # Tamaño seguro de la MTU
```
# Probar
### Levantar containers
```
docker compose -f docker/virtual-lab/compose.yml down
docker compose -f docker/virtual-lab/compose.yml up -d --build
```

### Ver los contenedores y buscar su nombre o su id
```
    docker ps
```
### Entrar en los contenedores

```
docker exec -it <node1_container_id> /bin/bash
```
### Ejecutar comandos
```
python3 /app/src/l2msg/cli/__main__.py
```

## Lo mismo pero en Local
```
# 1) Averigua el binario REAL de python3
readlink -f "$(command -v python3)"

# Suponiendo que imprime /usr/bin/python3.12 (ajusta si te da otra ruta)
sudo setcap cap_net_raw+ep /usr/bin/python3.12

# 2) Verifica
getcap /usr/bin/python3.12
```



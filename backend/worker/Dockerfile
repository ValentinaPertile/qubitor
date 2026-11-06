# Se construye con backend/ como contexto:
#   docker build -f backend/worker/Dockerfile backend
# Usamos una imagen base oficial de Python ligera
FROM python:3.11-slim

# Configuramos variables de entorno para evitar crear .pyc y forzar stdout sin buffer
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    # Directorio de trabajo seguro para los repositorios
    REPOS_DIR=/tmp/scans

# Instalamos Git (requerido por Módulo E) y dependencias de sistema limpiando el caché
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    && rm -rf /var/lib/apt/lists/*

# Creamos un usuario no privilegiado (qubitor) y el grupo
RUN groupadd -r qubitor_group && useradd -r -g qubitor_group qubitor

# Preparamos los directorios necesarios y asignamos permisos al usuario no root
RUN mkdir -p /app ${REPOS_DIR} \
    && chown -R qubitor:qubitor_group /app ${REPOS_DIR}

# Cambiamos al directorio de trabajo de la app
WORKDIR /app

# Copiamos el archivo de dependencias e instalamos (como root, pero quedan disponibles globalmente)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copiamos el código del backend (incluyendo el app/ y worker/)
COPY --chown=qubitor:qubitor_group . /app/

# Cambiamos al usuario no privilegiado
USER qubitor

# REDIS_URL se carga en el panel de Render; la lee app/config.py al arrancar.
CMD ["python", "-m", "app.worker.run"]

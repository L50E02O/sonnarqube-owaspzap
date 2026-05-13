# Caso 6 - Login sin fatiga (Brute Force)

Este repositorio contiene dos aplicaciones Flask simples para analizar vulnerabilidades y mejoras frente a ataques de fuerza bruta.

Archivos principales:

- `vulnerable_app.py`: implementación vulnerable.
- `secure_app.py`: versión mejorada con medidas básicas.
- `render.yaml`: configuración para desplegar ambas apps en Render.

## Requisitos

Instala dependencias:

```bash
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

## Ejecutar localmente

App vulnerable:

```bash
python vulnerable_app.py
```

App segura:

```bash
python secure_app.py
```

## Despliegue en Render

1. Sube este repositorio a GitHub.
2. En Render, crea un nuevo servicio desde un Blueprint usando `render.yaml`.
3. Render levantará dos servicios:
	- `caso-6-vulnerable`
	- `caso-6-secure`
4. Cada uno usa `gunicorn` y el puerto que Render inyecta con `PORT`.

Comandos que usa Render:

```bash
pip install -r requirements.txt
gunicorn vulnerable_app:app --bind 0.0.0.0:$PORT
gunicorn secure_app:app --bind 0.0.0.0:$PORT
```

## Nota importante

La versión segura sigue usando memoria en proceso para bloquear usuarios y guardar MFA. Para una demo sirve, pero en producción conviene Redis o una base de datos.

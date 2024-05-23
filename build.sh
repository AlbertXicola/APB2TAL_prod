#!/usr/bin/env bash
# exit on error
set -o errexit

# Instalar las dependencias desde requirements.txt
pip install -r requirements.txt

# Recopilar archivos estáticos
python manage.py collectstatic --no-input

# Aplicar migraciones de la base de datos
python manage.py makemigrations

python manage.py migrate
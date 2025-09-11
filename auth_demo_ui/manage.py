#!/usr/bin/env python
"""Django's command-line utility for administrative tasks."""
import os
import sys
from decouple import Config, RepositoryEnv
from pathlib import Path
from django.core.management import execute_from_command_line

BASE_DIR = Path(__file__).resolve().parent
ENV = os.getenv("ENV")
ENV_FILE = BASE_DIR / (f".env.{ENV}" if ENV else ".env")

if not ENV_FILE.exists():
    raise FileNotFoundError(f"❌ {ENV_FILE} not found")

config = Config(RepositoryEnv(str(ENV_FILE)))
os.environ.setdefault("DJANGO_SETTINGS_MODULE", "auth_demo_ui.settings")

def main():
    try:
        from django.core.management import execute_from_command_line
    except ImportError as exc:
        raise ImportError(
            "Couldn't import Django. Are you sure it's installed and "
            "available on your PYTHONPATH environment variable? Did you "
            "forget to activate a virtual environment?"
        ) from exc
     
    if len(sys.argv) >= 2 and sys.argv[1] == "runserver":
        if len(sys.argv) == 2:
            host = config("HOST", default="127.0.0.1")
            port = config("PORT", default="8000")
            sys.argv.append(f"{host}:{port}")
    
    execute_from_command_line(sys.argv)


if __name__ == '__main__':
    main()

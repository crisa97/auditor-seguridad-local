#! /usr/bin/env python3
import argparse
import os
import sys
import signal
import datetime
import logging

from src.infrastructure.config import settings
from src.infrastructure.di import (
    get_analizador,
    get_validar_api_key,
    get_analisis_repository,
)
from src.domain.enums import EstadoAnalisis

log = logging.getLogger("cli.analizador")


def _confirmar(prompt_msg, opciones_afirmativas, opciones_negativas):
    while True:
        r = input(prompt_msg).strip().lower()
        if r in opciones_afirmativas:
            return True
        if r in opciones_negativas:
            return False
        print("Por favor, responda 's' o 'n'.")


def signal_handler(sig, frame):
    print("\nInterrupcion detectada (Ctrl+C).")
    afirmativas = ('s', 'si')
    negativas = ('n', 'no')

    if _confirmar("Desea cancelar el escaneo? (s/n): ", afirmativas, negativas):
        if _confirmar("Desea generar el informe parcial? (s/n): ", afirmativas, negativas):
            print("Generando informe parcial...")
        print("Saliendo.")
        sys.exit(0)
    else:
        print("Continuando escaneo...")


def submit_to_queue(project_path, api_key="", servicio_url=""):
    try:
        from src.tasks.analysis_tasks import analizar_proyecto
        task = analizar_proyecto.delay(project_path, api_key=api_key, servicio_url=servicio_url)
        print(f"Analisis encolado exitosamente.")
        print(f"   Task ID: {task.id}")
        return task.id
    except Exception as e:
        print(f"Error al encolar el analisis: {e}")
        sys.exit(1)


def show_queue_status(task_id):
    try:
        from src.tasks.celery_app import celery_app
        result = celery_app.AsyncResult(task_id)

        if result.state == "PENDING":
            print("Estado: PENDIENTE - esperando ser procesado.")
        elif result.state == "STARTED":
            print("Estado: EN PROCESO - el analisis se esta ejecutando.")
        elif result.state == "SUCCESS":
            data = result.result
            print("Estado: COMPLETADO.")
            if isinstance(data, dict):
                print(f"   ID de analisis: {data.get('analisis_id', 'N/A')}")
                print(f"   Archivos analizados: {data.get('total_files', 'N/A')}")
                print(f"   Reporte TXT: {data.get('reporte_txt', 'N/A')}")
                print(f"   Reporte PDF: {data.get('reporte_pdf', 'N/A')}")
        elif result.state == "FAILURE":
            print(f"Estado: FALLIDO.")
            print(f"   Error: {result.info}")
        elif result.state == "RETRY":
            print("Estado: REINTENTANDO.")
        else:
            print(f"Estado: {result.state}")
    except Exception as e:
        print(f"Error al consultar estado: {e}")


def list_queue_jobs():
    try:
        repo = get_analisis_repository()
        analisis_list = repo.list_all(limit=10)
        if not analisis_list:
            print("No hay analisis registrados.")
            return
        print(f"{'ID':<30} {'PROYECTO':<40} {'ESTADO':<15} {'FECHA':<25}")
        print("-" * 110)
        for a in analisis_list:
            print(f"{a.id:<30} {a.project_path[-38:]:<40} {a.estado:<15} "
                  f"{a.timestamp.strftime('%Y-%m-%d %H:%M:%S'):<25}")
    except Exception as e:
        print(f"Error al listar analisis: {e}")


def main():
    signal.signal(signal.SIGINT, signal_handler)

    parser = argparse.ArgumentParser(
        description="Analizador de seguridad local con Ollama + ChromaDB + MongoDB",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Ejemplos:
  %(prog)s /ruta/al/proyecto              # Analisis directo
  %(prog)s --queue /ruta/al/proyecto      # Encolar analisis via Celery
  %(prog)s --status <task_id>             # Ver estado de tarea encolada
  %(prog)s --list                          # Listar analisis realizados
  %(prog)s --update-nvd /ruta/al/proyecto # Forzar actualizacion NVD
        """,
    )
    parser.add_argument("project_path", nargs="?", help="Ruta al directorio del proyecto")
    parser.add_argument("--queue", action="store_true",
                        help="Encolar el analisis en Celery en lugar de ejecutarlo directamente")
    parser.add_argument("--status", metavar="TASK_ID",
                        help="Consultar el estado de una tarea encolada")
    parser.add_argument("--list", action="store_true",
                        help="Listar todos los analisis registrados")
    parser.add_argument("--update-nvd", action="store_true",
                        help="Forzar actualizacion de la base NVD")
    parser.add_argument("--api-key", metavar="KEY",
                        help="API key para autenticacion contra el servicio de validacion")
    parser.add_argument("--enviar", metavar="URL",
                        help="Enviar resultados del analisis al servicio de validacion")

    args = parser.parse_args()

    api_key = args.api_key or os.getenv("ANALIZADOR_API_KEY", "")
    if api_key:
        log.info("Validando API key...")
        validador = get_validar_api_key()
        es_valida, msg, datos = validador.execute(api_key)
        if not es_valida:
            log.error("API key invalida: %s", msg)
            print(f"Error: {msg}")
            sys.exit(1)
        log.info("API key valida - cliente: %s", datos.get("nombre_cliente", "desconocido"))
    else:
        log.info("Sin API key - modo sin autenticacion.")

    if args.update_nvd:
        print("Forzando actualizacion de la base NVD...")
        from src.infrastructure.di import get_sincronizador_nvd
        get_sincronizador_nvd().execute()
        return

    if args.status:
        show_queue_status(args.status)
        return

    if args.list:
        list_queue_jobs()
        return

    if args.queue:
        if not args.project_path:
            print("Debes especificar la ruta del proyecto para encolar.")
            sys.exit(1)
        project_path = os.path.abspath(args.project_path)
        if not os.path.isdir(project_path):
            print(f"Error: la ruta '{project_path}' no es un directorio valido.")
            sys.exit(1)
        submit_to_queue(project_path, api_key=api_key, servicio_url=args.enviar or "")
        return

    if not args.project_path:
        parser.print_help()
        sys.exit(1)

    project_path = os.path.abspath(args.project_path)
    if not os.path.isdir(project_path):
        print(f"Error: la ruta '{project_path}' no es un directorio valido.")
        sys.exit(1)

    analizador = get_analizador()
    result = analizador.execute(
        project_path=project_path,
        api_key=api_key,
        servicio_url=args.enviar or "",
    )

    print(f"\nAnalisis completado. Archivos analizados: {result.get('total_files', 0)}.")
    print(f"   TXT: {result.get('reporte_txt', 'N/A')}")
    print(f"   PDF: {result.get('reporte_pdf', 'N/A')}")
    print(f"   MongoDB ID: {result.get('analisis_id', 'N/A')}")


if __name__ == "__main__":
    main()

import re

main_path = '/app/backend/open_webui/main.py'
with open(main_path) as f:
    content = f.read()

if 'openwebui_inject' not in content:
    content = 'import openwebui_inject\n' + content
    content = re.sub(
        r'(app = FastAPI\([^)]+\))',
        r'\1\nopenwebui_inject.patch_openwebui(app)',
        content
    )
    with open(main_path, 'w') as f:
        f.write(content)
    print('Middleware de validacion inyectado en Open WebUI')
else:
    print('Middleware ya presente, saltando patch.')

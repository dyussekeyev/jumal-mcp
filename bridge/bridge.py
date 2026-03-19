import json
import requests
from fastmcp import FastMCP

# Инициализация MCP-сервера
mcp = FastMCP("MCP-Jumal", description="Junior Malware Analyst Bridge")

# Адрес нашего изолированного Docker-воркера
WORKER_URL = "http://localhost:8000/api/v1"

@mcp.tool()
def analyze_file_triage(file_path: str) -> str:
    """
    Выполняет первичный триаж вредоносного файла. 
    Считает хэши (MD5, SHA1, SHA256), размер файла и запускает сканирование Detect It Easy (DIE).
    Используйте этот инструмент первым для понимания природы файла, наличия упаковщиков или протекторов.
    
    Args:
        file_path: Имя файла или относительный путь внутри директории с семплами.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/triage",
            json={"file_path": file_path},
            timeout=15  # Таймаут чуть больше, чем внутри воркера
        )
        response.raise_for_status()
        # Возвращаем ИИ красиво отформатированный JSON в виде строки
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Ошибка при связи с изолированным Worker'ом: {str(e)}"


@mcp.tool()
def extract_pe_info(file_path: str) -> str:
    """
    Выполняет глубокий анализ структуры PE-файлов (Windows Executable, DLL).
    Извлекает imphash, количество секций и выявляет аномалии (например, секции с высокой энтропией).
    Используйте это, если анализ триажа показал, что это PE-файл.
    
    Args:
        file_path: Имя файла или относительный путь внутри директории с семплами.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/pe-info",
            json={"file_path": file_path},
            timeout=15
        )
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Ошибка при связи с изолированным Worker'ом: {str(e)}"


if __name__ == "__main__":
    # Метод .run() по умолчанию запускает сервер в режиме stdio (стандартный ввод/вывод),
    # что является стандартом для взаимодействия с десктопными клиентами (например, Claude Desktop).
    mcp.run()

import json
import os
import requests
from fastmcp import FastMCP

# Инициализация MCP-сервера
mcp = FastMCP("MCP-Jumal", description="Junior Malware Analyst Bridge")

# Адрес нашего изолированного Docker-воркера (configurable via env)
WORKER_URL = os.environ.get("WORKER_URL", "http://localhost:8000/api/v1")

# Получаем ключ из переменных окружения
VT_API_KEY = os.environ.get("VT_API_KEY")

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
            timeout=60  # Таймаут чуть больше, чем внутри воркера
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
            timeout=60
        )
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Ошибка при связи с изолированным Worker'ом: {str(e)}"


@mcp.tool()
def check_virustotal(file_hash: str) -> str:
    """
    Проверяет репутацию файла по его хэшу (MD5, SHA-1 или SHA-256) в базе VirusTotal.
    Используйте этот инструмент ПОСЛЕ получения хэша из инструмента analyze_file_triage.
    Возвращает статистику детектов антивирусов и связанные теги.
    
    Args:
        file_hash: Строка с хэшем файла.
    """
    if not VT_API_KEY:
        return "Ошибка: Ключ VT_API_KEY не настроен на сервере."

    headers = {
        "accept": "application/json",
        "x-apikey": VT_API_KEY
    }
    
    # Используем API v3
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    
    try:
        response = requests.get(url, headers=headers, timeout=10)
        
        # Если файл не найден на VT — это тоже важный индикатор (возможно, APT или уникальный семпл)
        if response.status_code == 404:
            return json.dumps({"status": "not_found", "message": "Семпл не найден в базе VirusTotal. Возможно, это угроза нулевого дня."})
            
        response.raise_for_status()
        data = response.json().get("data", {})
        attributes = data.get("attributes", {})
        
        # Извлекаем только самое важное, чтобы не переполнять контекст LLM
        stats = attributes.get("last_analysis_stats", {})
        result = {
            "status": "found",
            "meaningful_name": attributes.get("meaningful_name", "Unknown"),
            "type_description": attributes.get("type_description", "Unknown"),
            "reputation_score": attributes.get("reputation", 0),
            "detections": {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
                "undetected": stats.get("undetected", 0)
            },
            "popular_threat_category": [
                cat.get("value") 
                for cat in attributes.get("popular_threat_classification", {}).get("popular_threat_category", [])
            ]
        }
        
        return json.dumps(result, indent=2)

    except requests.exceptions.RequestException as e:
        return f"Ошибка при запросе к VirusTotal API: {str(e)}"


@mcp.tool()
def scan_yara(file_path: str) -> str:
    """
    Сканирует файл локальным набором YARA-правил для выявления известных семейств ВПО, 
    специфичных паттернов кода или криптографических констант.
    Используйте этот инструмент для проверки файла на известные сигнатуры вашей организации.
    
    Args:
        file_path: Имя файла или относительный путь внутри директории с семплами.
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/yara",
            json={"file_path": file_path},
            timeout=30  # YARA может работать дольше, чем обычный триаж, если правил тысячи
        )
        response.raise_for_status()
        
        data = response.json()
        if data.get("error"):
            return json.dumps({"status": "error", "message": data["error"]}, indent=2)
            
        if not data.get("matches"):
            return json.dumps({"status": "clean", "message": "Ни одно YARA правило не сработало."}, indent=2)
            
        return json.dumps({
            "status": "matched",
            "triggered_rules": data["matches"]
        }, indent=2)

    except requests.exceptions.RequestException as e:
        return f"Ошибка при связи с изолированным Worker'ом: {str(e)}"


@mcp.tool()
def get_strings(file_path: str, min_length: int = 4) -> str:
    """
    Extracts ASCII and Unicode strings from the file and identifies potential IOCs
    (URLs, IPs, emails, file paths) using regex filters.
    Use this tool to find embedded indicators of compromise.
    
    Args:
        file_path: File name or relative path inside the samples directory.
        min_length: Minimum string length to extract (default: 4).
    """
    try:
        response = requests.post(
            f"{WORKER_URL}/strings",
            json={"file_path": file_path, "min_length": min_length},
            timeout=60
        )
        response.raise_for_status()
        return json.dumps(response.json(), indent=2)
    except requests.exceptions.RequestException as e:
        return f"Error communicating with Worker: {str(e)}"


if __name__ == "__main__":
    # Метод .run() по умолчанию запускает сервер в режиме stdio (стандартный ввод/вывод),
    # что является стандартом для взаимодействия с десктопными клиентами (например, Claude Desktop).
    mcp.run()

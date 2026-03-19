import os
import hashlib
import subprocess
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from functools import lru_cache
import yara
import lief
import pefile

app = FastAPI(
    title="Jumal Worker API",
    description="Internal API for malware static analysis (Isolated)",
    version="1.0.0"
)

# Базовая директория, примонтированная в Read-Only
SAMPLES_DIR = Path("/samples")

# Базовая директория для YARA правил
RULES_DIR = Path("/rules")

# --- Модели данных (Схемы) ---

class FileRequest(BaseModel):
    # Ожидаем относительный путь или имя файла внутри /samples
    file_path: str = Field(..., description="Path to the file relative to /samples directory")

class TriageResponse(BaseModel):
    md5: str
    sha1: str
    sha256: str
    file_size: int
    die_output: str | None = None

class PEInfoResponse(BaseModel):
    imphash: str | None
    is_dll: bool
    is_exe: bool
    number_of_sections: int
    suspicious_sections: list[str]

class YaraResponse(BaseModel):
    matches: list[str]
    error: str | None = None

# --- Утилиты Безопасности ---

def get_safe_path(requested_path: str) -> Path:
    """
    Критически важная функция: защита от Directory Traversal.
    Гарантирует, что итоговый путь не выходит за пределы /samples.
    """
    try:
        # Убираем начальные слеши, чтобы путь не стал абсолютным от корня ОС
        clean_path = requested_path.lstrip("\\/")
        full_path = (SAMPLES_DIR / clean_path).resolve()
        
        # Надёжная проверка (Python 3.9+)
        if not full_path.is_relative_to(SAMPLES_DIR.resolve()):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Path traversal attempt detected"
            )
        
        if not full_path.exists() or not full_path.is_file():
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found"
            )
        
        return full_path

    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Invalid or unsafe file path: {str(e)}"
        )

# --- Вспомогательные утилиты ---

@lru_cache(maxsize=1)
def _compile_yara_rules() -> yara.Rules | None:
    rule_filepaths = {}
    if RULES_DIR.exists():
        for rule_file in RULES_DIR.glob("*.yar"):
            rule_filepaths[rule_file.stem] = str(rule_file)
    if not rule_filepaths:
        return None
    return yara.compile(filepaths=rule_filepaths)

# --- Эндпоинты (Инструменты) ---

@app.post("/api/v1/triage", response_model=TriageResponse)
async def analyze_file_triage(request: FileRequest):
    """
    Базовый триаж: хэширование и запуск Detect It Easy (diec).
    """
    target_file = get_safe_path(request.file_path)
    
    # 1. Считаем хэши блоками (чтобы не грузить память огромными файлами)
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    
    with open(target_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)

    # 2. Запуск DIE (Detect It Easy) через subprocess с таймаутом
    die_result = None
    try:
        # Используем diec (консольную версию), ключ -j выдает JSON, но мы пока возьмем простой текст -b (brief)
        # Ограничиваем выполнение 10 секундами
        proc = subprocess.run(
            ["diec", "-b", str(target_file)], 
            capture_output=True, 
            text=True, 
            timeout=10
        )
        if proc.returncode == 0:
            die_result = proc.stdout.strip()
    except subprocess.TimeoutExpired:
        die_result = "Timeout: DIE scan took too long."
    except Exception as e:
        die_result = f"Error running DIE: {e}"

    return TriageResponse(
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
        file_size=target_file.stat().st_size,
        die_output=die_result
    )


@app.post("/api/v1/pe-info", response_model=PEInfoResponse)
async def extract_pe_info(request: FileRequest):
    """
    Глубокий анализ PE-файла. Используем pefile для imphash и LIEF для парсинга структуры.
    """
    target_file = get_safe_path(request.file_path)
    
    suspicious_sections = []
    imphash_val = None
    
    try:
        # 1. Получаем imphash через pefile
        pe = pefile.PE(str(target_file))
        imphash_val = pe.get_imphash()
        pe.close()
        
        # 2. Парсим структуру через LIEF
        binary = lief.parse(str(target_file))
        if not isinstance(binary, lief.PE.Binary):
            raise HTTPException(status_code=400, detail="Not a valid PE file")

        # Простейшая эвристика: ищем секции с аномальной энтропией (часто признак упаковщика)
        for section in binary.sections:
            if section.entropy > 7.5:
                suspicious_sections.append(f"{section.name} (High Entropy: {section.entropy:.2f})")
            if section.size == 0:
                suspicious_sections.append(f"{section.name} (Zero Size)")

        return PEInfoResponse(
            imphash=imphash_val,
            is_dll=binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.DLL),
            is_exe=binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE),
            number_of_sections=len(binary.sections),
            suspicious_sections=suspicious_sections
        )

    except pefile.PEFormatError:
        raise HTTPException(status_code=400, detail="Invalid PE format for pefile")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

@app.post("/api/v1/yara", response_model=YaraResponse)
async def scan_yara(request: FileRequest):
    """
    Сканирование файла предоставленными YARA-правилами.
    """
    target_file = get_safe_path(request.file_path)
    
    try:
        # Для MVP: собираем все .yar файлы из примонтированной папки
        rule_filepaths = {}
        if RULES_DIR.exists():
            for rule_file in RULES_DIR.glob("*.yar"):
                # yara.compile ожидает словарь вида {'namespace': 'path_to_file'}
                rule_filepaths[rule_file.stem] = str(rule_file)

        if not rule_filepaths:
            return YaraResponse(matches=[], error="В папке /rules не найдено .yar файлов.")

        # Компилируем правила и запускаем сканирование
        # (В production для CERT правила лучше компилировать один раз при старте воркера, чтобы экономить время)
        rules = yara.compile(filepaths=rule_filepaths)
        matches = rules.match(str(target_file))
        
        # matches - это список объектов yara.Match. Извлекаем только имена сработавших правил
        match_names = [match.rule for match in matches]
        
        return YaraResponse(matches=match_names)

    except yara.Error as e:
        return YaraResponse(matches=[], error=f"Ошибка YARA: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Внутренняя ошибка при сканировании: {str(e)}")

import os
import hashlib
import subprocess
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
import lief
import pefile

app = FastAPI(
    title="Jumal Worker API",
    description="Internal API for malware static analysis (Isolated)",
    version="1.0.0"
)

# Базовая директория, примонтированная в Read-Only
SAMPLES_DIR = Path("/samples")

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
        
        # Проверяем, что итоговый путь действительно начинается с /samples
        if not str(full_path).startswith(str(SAMPLES_DIR)):
            raise ValueError("Path traversal attempt detected")
            
        if not full_path.exists() or not full_path.is_file():
            raise ValueError("File not found")
            
        return full_path
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Invalid or unsafe file path: {str(e)}"
        )

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
            is_dll=binary.has_configuration, # Упрощенно
            is_exe=binary.header.has_characteristic(lief.PE.Header.CHARACTERISTICS.EXECUTABLE_IMAGE),
            number_of_sections=len(binary.sections),
            suspicious_sections=suspicious_sections
        )

    except pefile.PEFormatError:
        raise HTTPException(status_code=400, detail="Invalid PE format for pefile")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Analysis error: {str(e)}")

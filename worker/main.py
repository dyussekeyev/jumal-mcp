import hashlib
import asyncio
import math
import re
from collections import Counter
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from pydantic import BaseModel, Field
from functools import lru_cache
import yara
import lief
import pefile
import ssdeep
import magic

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
    ssdeep_hash: str | None = None
    imphash: str | None = None
    file_size: int
    mime_type: str | None = None
    file_entropy: float | None = None
    die_output: str | None = None

class StringsRequest(BaseModel):
    file_path: str = Field(..., description="Path to the file relative to /samples directory")
    min_length: int = Field(4, description="Minimum string length", ge=1, le=100)

class StringsResponse(BaseModel):
    total_strings: int
    strings: list[str]
    ioc_candidates: dict  # keys: "urls", "ips", "emails", "file_paths"

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

    except HTTPException:
        raise  # Re-raise HTTP exceptions as-is
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, 
            detail=f"Invalid or unsafe file path: {str(e)}"
        )

# --- Вспомогательные утилиты ---

def calculate_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    counter = Counter(data)
    length = len(data)
    entropy = -sum((count / length) * math.log2(count / length) for count in counter.values())
    return round(entropy, 4)

@lru_cache(maxsize=1)
def _compile_yara_rules() -> yara.Rules | None:
    rule_filepaths = {}
    if RULES_DIR.exists():
        for rule_file in RULES_DIR.glob("*.yar"):
            rule_filepaths[rule_file.stem] = str(rule_file)
        for rule_file in RULES_DIR.glob("*.yara"):
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

    # Guard: for entropy we buffer the whole file; cap at 200 MB to stay within memory limits
    MAX_TRIAGE_FILE_SIZE = 200 * 1024 * 1024  # 200 MB
    file_size = target_file.stat().st_size

    # 1. Считаем хэши блоками (чтобы не грузить память огромными файлами)
    md5_hash = hashlib.md5()
    sha1_hash = hashlib.sha1()
    sha256_hash = hashlib.sha256()
    # Accumulate bytes for entropy only when below the size cap
    file_data: bytearray | None = bytearray() if file_size <= MAX_TRIAGE_FILE_SIZE else None

    with open(target_file, "rb") as f:
        for byte_block in iter(lambda: f.read(4096), b""):
            md5_hash.update(byte_block)
            sha1_hash.update(byte_block)
            sha256_hash.update(byte_block)
            if file_data is not None:
                file_data.extend(byte_block)

    # 2. ssdeep fuzzy hash
    ssdeep_hash = None
    try:
        ssdeep_hash = ssdeep.hash_from_file(str(target_file))
    except Exception:
        pass

    # 3. MIME type via python-magic
    mime_type = None
    try:
        mime_type = magic.from_file(str(target_file), mime=True)
    except Exception:
        pass

    # 4. Shannon entropy of entire file (skipped for very large files)
    file_entropy = calculate_entropy(bytes(file_data)) if file_data is not None else None

    # 5. imphash via pefile (PE files only)
    imphash_val = None
    try:
        pe = pefile.PE(str(target_file))
        imphash_val = pe.get_imphash() or None
        pe.close()
    except Exception:
        pass

    # 6. Запуск DIE (Detect It Easy) через subprocess с таймаутом
    die_result = None
    try:
        # Используем diec (консольную версию), ключ -b (brief)
        proc = await asyncio.create_subprocess_exec(
            "diec", "-b", str(target_file),
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        try:
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            if proc.returncode == 0:
                die_result = stdout.decode().strip()
        except asyncio.TimeoutError:
            proc.kill()
            die_result = "Timeout: DIE scan took too long."
    except Exception as e:
        die_result = f"Error running DIE: {e}"

    return TriageResponse(
        md5=md5_hash.hexdigest(),
        sha1=sha1_hash.hexdigest(),
        sha256=sha256_hash.hexdigest(),
        ssdeep_hash=ssdeep_hash,
        imphash=imphash_val,
        file_size=file_size,
        mime_type=mime_type,
        file_entropy=file_entropy,
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
        rules = _compile_yara_rules()
        if rules is None:
            return YaraResponse(matches=[], error="No .yar/.yara rule files found in /rules.")
        matches = rules.match(str(target_file))
        match_names = [match.rule for match in matches]
        return YaraResponse(matches=match_names)
    except yara.Error as e:
        return YaraResponse(matches=[], error=f"YARA error: {str(e)}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal scan error: {str(e)}")


@app.post("/api/v1/strings", response_model=StringsResponse)
async def get_strings(request: StringsRequest):
    """
    Извлекает ASCII и Unicode строки из файла и фильтрует потенциальные IOC.
    """
    target_file = get_safe_path(request.file_path)
    min_len = request.min_length

    # Guard against loading excessively large files entirely into memory
    MAX_STRINGS_FILE_SIZE = 50 * 1024 * 1024  # 50 MB
    if target_file.stat().st_size > MAX_STRINGS_FILE_SIZE:
        raise HTTPException(status_code=400, detail="File too large for string extraction (max 50 MB)")

    with open(target_file, "rb") as f:
        data = f.read()

    # Build patterns with validated integer (Pydantic already enforces ge=1, le=100)
    min_len_str = str(int(min_len))

    # Extract ASCII strings
    ascii_pattern = re.compile(rb'[\x20-\x7e]{' + min_len_str.encode() + rb',}')
    ascii_strings = [m.group(0).decode("ascii") for m in ascii_pattern.finditer(data)]

    # Extract Unicode (UTF-16 LE) strings
    unicode_pattern = re.compile(rb'(?:[\x20-\x7e]\x00){' + min_len_str.encode() + rb',}')
    unicode_strings = [m.group(0).decode("utf-16-le") for m in unicode_pattern.finditer(data)]

    all_strings = ascii_strings + unicode_strings

    # IOC regex filters — validated IP octet ranges (0-255)
    ip_re = re.compile(
        r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'
    )
    url_re = re.compile(r'https?://[^\s\'"<>]+', re.IGNORECASE)
    email_re = re.compile(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
    # Windows paths: C:\... ; Unix common sensitive paths: /etc, /usr, /bin, etc.
    windows_path_re = re.compile(r'[a-zA-Z]:\\[^\s\'"<>]*')
    unix_path_re = re.compile(r'/(?:etc|usr|bin|tmp|home|var|proc|sys|windows|system32)[^\s\'"<>]*', re.IGNORECASE)

    urls: set[str] = set()
    ips: set[str] = set()
    emails: set[str] = set()
    file_paths: set[str] = set()

    for s in all_strings:
        urls.update(url_re.findall(s))
        ips.update(ip_re.findall(s))
        emails.update(email_re.findall(s))
        file_paths.update(windows_path_re.findall(s))
        file_paths.update(unix_path_re.findall(s))

    ioc_candidates = {
        "urls": list(urls),
        "ips": list(ips),
        "emails": list(emails),
        "file_paths": list(file_paths),
    }

    return StringsResponse(
        total_strings=len(all_strings),
        strings=all_strings,
        ioc_candidates=ioc_candidates,
    )

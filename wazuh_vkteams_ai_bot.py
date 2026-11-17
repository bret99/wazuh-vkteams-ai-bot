#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VK Teams [Workspace] SIEM Bot — Single-Node OpenSearch Aggregator & AI Analyzer
===================================================================
"""

import json
import os
import re
import shlex
import subprocess
import sys
import time
import urllib3
from datetime import datetime, timedelta, timezone
from concurrent.futures import ThreadPoolExecutor

import requests
from opensearchpy import OpenSearch

# Tokenization setup with fallback
try:
    import tiktoken
    TOKENIZER = tiktoken.get_encoding("cl100k_base")
except ImportError:
    TOKENIZER = None

TOKEN_THRESHOLD = 1_000_000
CHUNK_MAX_TOKENS = 400_000
CONTEXT_MAX_TOKENS = 950_000

# AI answer generation budget. Hidden reasoning tokens of the model are counted
# in max_tokens, so a small value exhausts the budget on thinking and the API
# returns an EMPTY content — the bot then sends an empty message and VK Teams
# rejects it with "Bad request". Reasoning is disabled and the budget is larger.
AI_MAX_TOKENS = 8000
AI_REASONING_EFFORT = "none"
AI_TIMEOUT = 600
AI_RETRIES = 3

# VK Teams message limits (long texts are sent in chunks below the server limit)
VK_TEXT_CHUNK_SIZE = 3500

# Attached file analysis limits
MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024
MAX_FILE_TEXT_CHARS = 12_000_000

ANALYZE_FILE_EXTS = {
    ".json", ".ndjson", ".jsonl", ".log", ".txt", ".csv", ".tsv", ".xml", ".yaml",
    ".yml", ".conf", ".cfg", ".ini", ".evtx.txt", ".md", ".sql", ".html", ".htm",
    ".py", ".sh", ".ps1", ".js", ".evt"
}

# Disable SSL warnings for self-signed certificates
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# =============================================================================
# CONFIGURATION
# =============================================================================
from access_tokens import (
    VK_TEAMS_TOKEN,
    VK_TEAMS_API_URL,
    AI_KEY,
    AI_URL,
    AI_MODEL,
    TARGET_USER_FIELDS,
    EXCLUDED_RULE_GROUPS,
    WAZUH_HOST,
    WAZUH_USER,
    WAZUH_PASS
)

ALLOWED_USERS = []

PERIOD_DELTAS = {
    "1h": (timedelta(hours=1), "1 hour"),
    "3h": (timedelta(hours=3), "3 hours"),
    "6h": (timedelta(hours=6), "6 hours"),
    "12h": (timedelta(hours=12), "12 hours"),
    "24h": (timedelta(hours=24), "24 hours"),
    "3d": (timedelta(days=3), "3 days"),
    "7d": (timedelta(days=7), "7 days"),
    "14d": (timedelta(days=14), "14 days"),
    "30d": (timedelta(days=30), "30 days")
}

# Default Prompt Templates
DEFAULT_USER_PROMPT_TEMPLATE = (
    "Проанализируй JSON-отчет событий безопасности как продвинутый SOC-аналитик. "
    "Ограничь свой ответ максимум в 1000 токенов/символов.\n\n"
    "Сформируй отчет строго в следующей структуре:\n\n"
    "🛡️ SOC AI: USER {target_val} Report\n\n"
    "📊 Events: {events_count}\n\n"
    "**Аналитический отчет SOC (Security Operations Center)**\n"
    "**Дата анализа:** {date_str}\n"
    "**Объект мониторинга:** Wazuh SIEM Node\n"
    "**Пользователь:** {target_val}\n"
    "**Временной диапазон:** {period_label}\n"
    "---\n"
    "📊 Краткое резюме (Executive Summary)\n"
    "[Краткие выводы: критичность, наличие IoC, уровень шума]\n\n"
    "---\n"
    "🔍 Детальный разбор ключевых событий\n"
    "1. [Категория события] -> Анализ -> Вердикт (False Positive / Шум / Требует проверки / Инцидент)\n\n"
    "---\n"
    "🛡️ Рекомендации для команды ИБ и IT\n"
    "1. [Конкретная рекомендация]\n\n"
    "**Статус отчета:** [Закрыт (False Positive / Noise) / Требует расследования]"
)

DEFAULT_HOST_PROMPT_TEMPLATE = (
    "Проанализируй JSON-отчет событий безопасности как продвинутый SOC-аналитик. "
    "Ограничь свой ответ максимум в 1000 токенов/символов.\n\n"
    "Сформируй отчет строго в следующей структуре:\n\n"
    "🛡️ SOC AI: HOST {target_val} Report\n\n"
    "📊 Events: {events_count}\n\n"
    "**Аналитический отчет SOC (Security Operations Center)**\n"
    "**Дата анализа:** {date_str}\n"
    "**Объект мониторинга:** Wazuh SIEM Node\n"
    "**Хост/Агент:** {target_val}\n"
    "**Временной диапазон:** {period_label}\n"
    "---\n"
    "📊 Краткое резюме (Executive Summary)\n"
    "[Краткие выводы: критичность, наличие IoC, уровень шума]\n\n"
    "---\n"
    "🔍 Детальный разбор ключевых событий\n"
    "1. [Категория события] -> Анализ -> Вердикт (False Positive / Шум / Требует проверки / Инцидент)\n\n"
    "---\n"
    "🛡️ Рекомендации для команды ИБ и IT\n"
    "1. [Конкретная рекомендация]\n\n"
    "**Статус отчета:** [Закрыт (False Positive / Noise) / Требует расследования]"
)

DEFAULT_FILE_PROMPT_TEMPLATE = (
    "Проанализируй приложенный файл как продвинутый SOC-аналитик. "
    "Отвечай на русском языке, структурировано, не более 4000 символов.\n\n"
    "Файл: {file_name}\n"
    "Размер: {file_size}\n\n"
    "Сформируй отчет строго в следующей структуре:\n\n"
    "📎 Анализ файла: {file_name}\n\n"
    "📊 Краткое резюме (Executive Summary)\n"
    "[Что это за данные, критичность, наличие IoC, уровень шума]\n\n"
    "🔍 Ключевые находки\n"
    "1. [Наблюдение] -> Анализ -> Вердикт (False Positive / Шум / Требует проверки / Инцидент)\n\n"
    "⚠️ Подозрительное / аномалии\n"
    "[Перечень аномалий, если есть]\n\n"
    "🛡️ Рекомендации для команды ИБ и IT\n"
    "1. [Конкретная рекомендация]\n\n"
    "**Статус:** [Закрыт / Требует расследования]"
)

# Global FSM storage and worker pool
USER_STATES = {}
EXECUTOR = ThreadPoolExecutor(max_workers=6)


# =============================================================================
# HELPER FUNCTIONS & TOKENIZATION
# =============================================================================
def count_tokens(text: str) -> int:
    """Calculate token count using tiktoken (cl100k_base) or fallback estimation."""
    if TOKENIZER:
        try:
            return len(TOKENIZER.encode(text))
        except Exception:
            pass
    return len(text) // 4


def split_events_into_chunks(events: list, max_chunk_tokens: int = CHUNK_MAX_TOKENS) -> list:
    """Split event array into chunks bounded by max token capacity."""
    chunks = []
    current_chunk = []
    current_tokens = 0

    for event in events:
        event_str = json.dumps(event, ensure_ascii=False)
        event_tokens = count_tokens(event_str)

        if current_tokens + event_tokens > max_chunk_tokens and current_chunk:
            chunks.append(current_chunk)
            current_chunk = [event]
            current_tokens = event_tokens
        else:
            current_chunk.append(event)
            current_tokens += event_tokens

    if current_chunk:
        chunks.append(current_chunk)

    return chunks


def sanitize_message_text(text) -> str:
    """Make text safe for the sendText endpoint (no empty payloads, no control chars)."""
    if text is None:
        return ""

    if not isinstance(text, str):
        text = str(text)

    # Break surrogate pairs produced by slicing/decoding, then drop lone surrogates
    text = text.encode("utf-8", "replace").decode("utf-8", "replace")

    # Remove NUL and most control characters, keep \n, \r and \t
    text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", "", text)
    text = text.replace("\r\n", "\n").replace("\r", "\n")

    return text.strip()


def split_text_for_vk(text: str, chunk_size: int = VK_TEXT_CHUNK_SIZE) -> list:
    """Split a long message into chunks, preferring newline boundaries."""
    if len(text) <= chunk_size:
        return [text]

    chunks = []
    remaining = text

    while len(remaining) > chunk_size:
        window = remaining[:chunk_size]
        cut = window.rfind("\n\n")
        if cut < chunk_size // 2:
            cut = window.rfind("\n")
        if cut < chunk_size // 2:
            cut = window.rfind(" ")
        if cut < chunk_size // 2:
            cut = chunk_size

        chunk = remaining[:cut].rstrip()
        if chunk:
            chunks.append(chunk)
        remaining = remaining[cut:].lstrip("\n")

    if remaining.strip():
        chunks.append(remaining.strip())

    return chunks or [text[:chunk_size]]


def is_text_like_file(filename: str, content: bytes) -> bool:
    """Decide whether an uploaded file can be analysed as text."""
    sample = content[:8192]

    # NUL bytes are a strong binary signal. Give UTF-16 a chance, reject otherwise.
    if b"\x00" in sample:
        try:
            sample.decode("utf-16")
            return True
        except (UnicodeDecodeError, UnicodeError):
            return False

    _, ext = os.path.splitext((filename or "").lower())
    if ext in ANALYZE_FILE_EXTS:
        return True

    try:
        sample.decode("utf-8")
        return True
    except UnicodeDecodeError:
        pass

    try:
        sample.decode("cp1251")
        return True
    except UnicodeDecodeError:
        return False


def decode_file_bytes(content: bytes) -> str:
    """Decode uploaded bytes trying encodings typical for SIEM exports."""
    for encoding in ("utf-8-sig", "utf-8", "cp1251", "utf-16"):
        try:
            return content.decode(encoding)
        except (UnicodeDecodeError, UnicodeError):
            continue
    return content.decode("utf-8", "replace")


def format_bytes(size: int) -> str:
    """Render a byte count in human readable form."""
    value = float(size)
    for unit in ("B", "KB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} B"
        value /= 1024.0
    return f"{value:.2f} GB"


def maybe_pretty_json(text: str) -> str:
    """Pretty-print JSON/NDJSON exports to make them more readable for the model."""
    stripped = text.strip()
    if not stripped:
        return text

    # Single JSON document: pretty-print only if it is not too large
    if stripped[0] in "[{" and stripped[-1] in "]}" and len(stripped) <= 5_000_000:
        try:
            return json.dumps(json.loads(stripped), ensure_ascii=False, indent=1)
        except Exception:
            pass

    # NDJSON / JSONL: one JSON object per line
    lines = stripped.splitlines()
    if len(lines) > 1:
        probe = [line for line in lines[:5] if line.strip()]
        if probe and all(line.lstrip().startswith("{") for line in probe):
            normalized = []
            parsed_any = False
            for line in lines:
                line = line.strip()
                if not line:
                    continue
                try:
                    normalized.append(json.dumps(json.loads(line), ensure_ascii=False))
                    parsed_any = True
                except Exception:
                    normalized.append(line)
            if parsed_any:
                return "\n".join(normalized)

    return text


def split_text_into_chunks(text: str, max_chunk_tokens: int = CHUNK_MAX_TOKENS) -> list:
    """Split long plain text into chunks under max_chunk_tokens, preferring newlines."""
    if count_tokens(text) <= max_chunk_tokens:
        return [text]

    # Keep a safety margin over the ~3.8 chars per token estimate
    max_chars = int(max_chunk_tokens * 3.4)
    chunks = []
    remaining = text

    while count_tokens(remaining) > max_chunk_tokens and len(remaining) > max_chars:
        window = remaining[:max_chars]
        cut = window.rfind("\n")
        if cut < max_chars // 2:
            cut = window.rfind(" ")
        if cut < max_chars // 2:
            cut = max_chars
        chunks.append(remaining[:cut])
        remaining = remaining[cut:]

    if remaining.strip():
        chunks.append(remaining)

    return chunks or [text]


def send_raw_prompt_to_router_ai(prompt: str) -> str:
    """Send isolated payload to RouterAI API with retries and empty-content detection.

    The model spends part of ``max_tokens`` on hidden reasoning tokens. With a
    small budget every token goes to reasoning and ``content`` comes back empty
    while ``finish_reason`` is ``length``; sending that empty string to VK Teams
    yields "Bad request". Reasoning is disabled here and an empty answer is
    turned into an explicit non-empty error message.
    """
    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": AI_MAX_TOKENS
    }
    if AI_REASONING_EFFORT:
        payload["reasoning_effort"] = AI_REASONING_EFFORT
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AI_KEY}"
    }

    last_error = "unknown error"

    for attempt in range(1, AI_RETRIES + 1):
        try:
            response = requests.post(AI_URL, headers=headers, json=payload, timeout=AI_TIMEOUT)
        except Exception as e:
            last_error = f"Failed to reach RouterAI API: {e}"
            print(f"⚠️ AI attempt {attempt}/{AI_RETRIES}: {last_error}")
            time.sleep(2 * attempt)
            continue

        try:
            result = response.json()
        except Exception:
            last_error = (
                f"RouterAI API Error [{response.status_code}]: "
                f"Non-JSON response ({response.text[:200]})"
            )
            print(f"⚠️ AI attempt {attempt}/{AI_RETRIES}: {last_error}")
            time.sleep(2 * attempt)
            continue

        # Provider does not understand reasoning_effort: retry once without it
        if (response.status_code in (400, 422)
                and "reasoning_effort" in payload
                and "reasoning" in json.dumps(result, ensure_ascii=False).lower()):
            print("⚠️ Provider rejected reasoning_effort, retrying without it.")
            payload.pop("reasoning_effort", None)
            continue

        if response.status_code == 200:
            choices = result.get("choices")
            if choices and isinstance(choices, list):
                choice = choices[0]
                message = choice.get("message", {})
                content = ((message.get("content") if isinstance(message, dict) else None) or "").strip()

                if content:
                    return content

                usage = result.get("usage") or {}
                reasoning_tokens = (usage.get("completion_tokens_details") or {}).get("reasoning_tokens")
                last_error = (
                    "RouterAI API вернул пустой ответ "
                    f"(finish_reason={choice.get('finish_reason')}, "
                    f"completion_tokens={usage.get('completion_tokens')}, "
                    f"reasoning_tokens={reasoning_tokens}). "
                    "Модель израсходовала лимит на reasoning — увеличьте AI_MAX_TOKENS "
                    "или уменьшите объем данных в запросе."
                )
                print(f"⚠️ AI attempt {attempt}/{AI_RETRIES}: {last_error}")
                time.sleep(2 * attempt)
                continue

            if "error" in result:
                err_val = result["error"]
                err_msg = err_val.get("message", str(err_val)) if isinstance(err_val, dict) else str(err_val)
                last_error = f"RouterAI API Error: {err_msg}"
            else:
                last_error = f"Malformed response structure from RouterAI API: {json.dumps(result)[:300]}"

            print(f"⚠️ AI attempt {attempt}/{AI_RETRIES}: {last_error}")
            time.sleep(2 * attempt)
            continue

        last_error = f"RouterAI API Error [{response.status_code}]: {response.text[:300]}"
        print(f"⚠️ AI attempt {attempt}/{AI_RETRIES}: {last_error}")
        time.sleep(2 * attempt)

    return f"❌ {last_error}"


# =============================================================================
# DATA FETCHING & AGGREGATION
# =============================================================================
def build_search_clauses(target_val: str, search_type: str) -> tuple:
    """Build OpenSearch should and must_not clauses with case-insensitive exclusions."""
    fields = ["agent.name"] if search_type == "host" else TARGET_USER_FIELDS
    should_clauses = []
    for field in fields:
        should_clauses.append({"term": {field: target_val}})
        should_clauses.append({"term": {f"{field}.keyword": target_val}})
        should_clauses.append({"match_phrase": {field: target_val}})

    must_not_clauses = []
    if EXCLUDED_RULE_GROUPS:
        normalized_exclusions = [g.lower() for g in EXCLUDED_RULE_GROUPS]
        must_not_clauses.append({"terms": {"rule.groups": normalized_exclusions}})
        must_not_clauses.append({"terms": {"rule.groups.keyword": normalized_exclusions}})

    return should_clauses, must_not_clauses


def fetch_wazuh_events(target_val: str, search_type: str, start_iso: str, end_iso: str) -> list:
    """Fetch events locally from Wazuh Node via OpenSearch client."""
    client = OpenSearch(
        hosts=WAZUH_HOST,
        http_auth=(WAZUH_USER, WAZUH_PASS),
        use_ssl=True,
        verify_certs=False,
        timeout=60,
        ssl_show_warn=False
    )

    should_clauses, must_not_clauses = build_search_clauses(target_val, search_type)

    query = {
        "size": 1000,
        "query": {
            "bool": {
                "must": [
                    {"bool": {"should": should_clauses, "minimum_should_match": 1}},
                    {"range": {"@timestamp": {"gte": start_iso, "lte": end_iso}}}
                ],
                "must_not": must_not_clauses
            }
        },
        "sort": [{"@timestamp": {"order": "desc"}}]
    }

    try:
        resp = client.search(index="wazuh-alerts*", body=query, scroll="5m")
        scroll_id = resp.get("_scroll_id")
        events = []

        while len(resp["hits"]["hits"]) > 0:
            for hit in resp["hits"]["hits"]:
                source = hit.get("_source", {})
                source["siem_node"] = "wazuh"
                events.append(source)

            resp = client.scroll(scroll_id=scroll_id, scroll="5m")
            scroll_id = resp.get("_scroll_id")

        if scroll_id:
            try:
                client.clear_scroll(scroll_id=scroll_id)
            except Exception:
                pass

        return events
    except Exception as e:
        print(f"❌ Error fetching Wazuh events: {e}")
        return []


def process_report_jq(raw_path: str, final_path: str) -> bool:
    """Strip unnecessary fields from raw report using jq utility."""
    jq_cmd = (
        f"jq 'map(del(.agent, .timestamp, .siem_node, "
        f".decoder, .input, .manager, .full_log, .full.log, .location, .id, "
        f".rule.level, .rule.id, .rule.mail, .rule.groups, .rule.pci_dss, "
        f".rule.hipaa, .rule.tsc, .rule.gdpr, .rule.gpdr, "
        f".win.eventdata.binary, .data.win.eventdata.binary))' "
        f"{shlex.quote(raw_path)} > {shlex.quote(final_path)}"
    )
    res = subprocess.run(jq_cmd, shell=True, capture_output=True, text=True)
    return res.returncode == 0 and os.path.exists(final_path)


def query_router_ai(json_data: list, target_val: str, search_type: str, period_label: str, custom_prompt: str = None) -> str:
    """Send report to RouterAI using single-pass or chunked evaluation with synthesis based on token count."""
    json_str = json.dumps(json_data, ensure_ascii=False)
    total_tokens = count_tokens(json_str)

    if total_tokens < min(TOKEN_THRESHOLD, CONTEXT_MAX_TOKENS):
        if custom_prompt:
            prompt = f"{custom_prompt}\n\nJSON data:\n{json_str}"
        else:
            template = DEFAULT_USER_PROMPT_TEMPLATE if search_type == "user" else DEFAULT_HOST_PROMPT_TEMPLATE
            prompt = template.format(
                target_val=target_val,
                events_count=len(json_data),
                date_str=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                period_label=period_label
            ) + f"\n\nJSON data:\n{json_str}"

        return send_raw_prompt_to_router_ai(prompt)

    # Multi-chunk processing for large datasets
    chunks = split_events_into_chunks(json_data, CHUNK_MAX_TOKENS)
    total_chunks = len(chunks)
    partial_reports = []

    for idx, chunk in enumerate(chunks, 1):
        chunk_json_str = json.dumps(chunk, ensure_ascii=False)
        if custom_prompt:
            chunk_prompt = (
                f"Это часть {idx} из {total_chunks} общего отчета событий безопасности.\n"
                f"{custom_prompt}\n\nJSON данные части {idx}:\n{chunk_json_str}"
            )
        else:
            template = DEFAULT_USER_PROMPT_TEMPLATE if search_type == "user" else DEFAULT_HOST_PROMPT_TEMPLATE
            chunk_prompt = template.format(
                target_val=f"{target_val} (Часть {idx}/{total_chunks})",
                events_count=len(chunk),
                date_str=datetime.now(timezone.utc).strftime("%Y-%m-%d"),
                period_label=period_label
            ) + f"\n\nJSON данные части {idx}:\n{chunk_json_str}"

        partial_res = send_raw_prompt_to_router_ai(chunk_prompt)
        if partial_res.startswith("❌"):
            return f"❌ Ошибка при анализе части {idx}/{total_chunks}: {partial_res}"
        partial_reports.append(f"--- Результат анализа части {idx}/{total_chunks} ---\n{partial_res}")

    combined_partials = "\n\n".join(partial_reports)
    synthesis_prompt = (
        f"Ниже приведены результаты независимого анализа {total_chunks} частей одного отчета безопасности для {search_type} '{target_val}'.\n"
        f"Временной диапазон: {period_label}.\n\n"
        f"Сформируй ИТОГОВЫЙ ЕДИНЫЙ SOC-ОТЧЕТ, объединив все ключевые находки, дубликаты и выводы из всех частей.\n"
        f"Придерживайся стандартной структуры отчета SOC (Краткое резюме, Детальный разбор ключевых событий, Рекомендации, Статус отчета).\n\n"
        f"ЧАСТНЫЕ ОЦЕНКИ ВСЕХ ЧАСТЕЙ:\n{combined_partials}"
    )

    return send_raw_prompt_to_router_ai(synthesis_prompt)


def query_router_ai_for_file(file_text: str, file_name: str, file_size: str, custom_prompt: str = None) -> str:
    """Analyse an arbitrary uploaded text file with the AI, chunking huge files."""
    prepared = maybe_pretty_json(file_text)

    if custom_prompt:
        base_prompt = f"{custom_prompt}\n\nПриложенный файл: {file_name} (размер: {file_size})."
    else:
        base_prompt = DEFAULT_FILE_PROMPT_TEMPLATE.format(file_name=file_name, file_size=file_size)

    if count_tokens(prepared) <= CHUNK_MAX_TOKENS:
        return send_raw_prompt_to_router_ai(f"{base_prompt}\n\nСодержимое файла:\n{prepared}")

    chunks = split_text_into_chunks(prepared, CHUNK_MAX_TOKENS)
    total_chunks = len(chunks)
    partial_reports = []

    for idx, chunk in enumerate(chunks, 1):
        chunk_tokens = count_tokens(chunk)
        chunk_prompt = (
            f"[Часть {idx} из {total_chunks}, ~{chunk_tokens} токенов]\n"
            f"{base_prompt}\n\n"
            f"Это фрагмент №{idx} файла `{file_name}`. "
            f"Проанализируй ТОЛЬКО этот фрагмент и кратко перечисли находки.\n\n"
            f"Содержимое фрагмента:\n{chunk}"
        )
        partial_res = send_raw_prompt_to_router_ai(chunk_prompt)
        if partial_res.startswith("❌"):
            return f"❌ Ошибка при анализе части {idx}/{total_chunks}: {partial_res}"
        partial_reports.append(f"--- Результат анализа части {idx}/{total_chunks} ---\n{partial_res}")

    synthesis_prompt = (
        f"Ты эксперт SOC. Файл `{file_name}` (размер: {file_size}) был разбит на "
        f"{total_chunks} частей из-за большого объема.\n\n"
        f"Сформируй единый сводный отчет по всему файлу, строго соблюдая структуру:\n\n"
        f"{DEFAULT_FILE_PROMPT_TEMPLATE.format(file_name=file_name, file_size=file_size)}\n\n"
        f"Промежуточные результаты по фрагментам:\n" + "\n\n".join(partial_reports)
    )

    return send_raw_prompt_to_router_ai(synthesis_prompt)


def cleanup_all_reports(target_val: str = None, search_type: str = "user"):
    """Clean up temporary report files on local host."""
    raw_file = f"/tmp/{search_type}_{target_val}_report.json" if target_val else ""
    final_file = "/tmp/final_report.json"

    for path in (raw_file, final_file):
        if path and os.path.exists(path):
            try:
                os.remove(path)
            except Exception as e:
                print(f"⚠️ Error removing local file {path}: {e}")


# =============================================================================
# VK TEAMS BOT CLIENT
# =============================================================================
class VKTeamsBot:
    def __init__(self, token: str, api_url: str):
        self.token = token
        self.api_url = api_url.rstrip("/")
        self.last_event_id = 0
        self.session = requests.Session()
        self.session.verify = False

    def _call(self, method: str, params: dict, use_post: bool = False, timeout: int = 60):
        url = f"{self.api_url}/{method}"
        base = {"token": self.token}
        base.update(params)

        try:
            if use_post:
                resp = self.session.post(url, data=base, timeout=timeout)
            else:
                resp = self.session.get(url, params=base, timeout=timeout)

            if resp.status_code == 200:
                data = resp.json()
                if not data.get("ok", True):
                    print(f"❌ API logical error [{method}]: {data.get('description', 'Unknown error')}")
                    return None
                return data
            return None
        except requests.exceptions.ReadTimeout:
            return None
        except Exception as e:
            print(f"❌ API network error [{method}]: {e}")
            return None

    def get_events(self, poll_time: int = 30):
        return self._call(
            "events/get",
            {"lastEventId": self.last_event_id, "pollTime": poll_time},
            timeout=poll_time + 10
        )

    def send_text(self, chat_id: str, text: str, keyboard: list = None):
        """Send message with sanitization and chunking support for large outputs."""
        text = sanitize_message_text(text)

        if not text:
            text = "⚠️ Пустой ответ от AI. Попробуйте повторить запрос."

        if len(text) <= VK_TEXT_CHUNK_SIZE:
            params = {"chatId": chat_id, "text": text}
            if keyboard:
                params["inlineKeyboardMarkup"] = json.dumps(keyboard, ensure_ascii=False)
            return self._call("messages/sendText", params, use_post=True)

        # Split on natural boundaries so Markdown/emoji are not broken
        chunks = split_text_for_vk(text, VK_TEXT_CHUNK_SIZE)
        for idx, chunk in enumerate(chunks):
            is_last = (idx == len(chunks) - 1)
            params = {"chatId": chat_id, "text": chunk}
            if is_last and keyboard:
                params["inlineKeyboardMarkup"] = json.dumps(keyboard, ensure_ascii=False)
            self._call("messages/sendText", params, use_post=True)

    def answer_callback(self, query_id: str, text: str = None):
        params = {"queryId": query_id}
        if text:
            params["text"] = text[:200]
        return self._call("messages/answerCallbackQuery", params)

    def get_file_info(self, file_id: str):
        """Resolve metadata (url/name/size) of an uploaded file."""
        data = self._call("files/getInfo", {"fileId": file_id}, timeout=60)
        if not data or not data.get("url"):
            return None
        return data

    def download_file(self, url: str, max_bytes: int = MAX_FILE_SIZE_BYTES) -> bytes:
        """Download an uploaded file into memory with a size guard."""
        resp = self.session.get(url, timeout=300, stream=True)
        resp.raise_for_status()

        chunks = []
        total = 0
        for chunk in resp.iter_content(65536):
            if not chunk:
                continue
            total += len(chunk)
            if total > max_bytes:
                raise ValueError(f"Файл превышает лимит {format_bytes(max_bytes)}")
            chunks.append(chunk)

        return b"".join(chunks)


# =============================================================================
# INLINE KEYBOARDS
# =============================================================================
def kb_main():
    return [
        [{"text": "👤 User activity", "callbackData": "act:user_activity", "style": "primary"}],
        [{"text": "💻 Host activity", "callbackData": "act:host_activity", "style": "primary"}],
        [{"text": "📎 Analyze attached file (AI)", "callbackData": "file:analyze", "style": "primary"}]
    ]


def kb_file_modes():
    return [
        [{"text": "👀 See default prompt", "callbackData": "file_see_prompt", "style": "primary"}],
        [{"text": "▶️ Analyze with default prompt", "callbackData": "file_run:default", "style": "primary"}],
        [{"text": "✍️ Analyze with my prompt", "callbackData": "file_run:custom", "style": "primary"}],
        [{"text": "❌ Cancel", "callbackData": "menu:main", "style": "attention"}]
    ]


def kb_prompt_options(search_type: str):
    return [
        [
            {"text": "👀 See default prompt", "callbackData": f"prompt_see:{search_type}", "style": "primary"},
            {"text": "▶️ Run default prompt", "callbackData": f"prompt_run:{search_type}", "style": "primary"}
        ],
        [{"text": "✍️ Enter your prompt", "callbackData": f"prompt_custom:{search_type}", "style": "primary"}],
        [{"text": "❌ Cancel", "callbackData": "menu:main", "style": "attention"}]
    ]


def kb_periods():
    return [
        [
            {"text": "⏱️ 1h", "callbackData": "period:1h", "style": "primary"},
            {"text": "⏱️ 3h", "callbackData": "period:3h", "style": "primary"},
            {"text": "⏱️ 6h", "callbackData": "period:6h", "style": "primary"}
        ],
        [
            {"text": "⏱️ 12h", "callbackData": "period:12h", "style": "primary"},
            {"text": "⏱️ 24h", "callbackData": "period:24h", "style": "primary"},
            {"text": "⏱️ 3d", "callbackData": "period:3d", "style": "primary"}
        ],
        [
            {"text": "⏱️ 7d", "callbackData": "period:7d", "style": "primary"},
            {"text": "⏱️ 14d", "callbackData": "period:14d", "style": "primary"},
            {"text": "⏱️ 30d", "callbackData": "period:30d", "style": "primary"}
        ],
        [{"text": "❌ Cancel", "callbackData": "menu:main", "style": "attention"}]
    ]


def kb_ai_decision():
    return [
        [
            {"text": "🤖 Send to AI", "callbackData": "ai:send", "style": "primary"},
            {"text": "🗑️ Not send to AI", "callbackData": "ai:cancel", "style": "attention"}
        ]
    ]


# =============================================================================
# ASYNC WORKERS & HANDLERS
# =============================================================================
def _check_access(user_id: str, chat_id: str, bot: VKTeamsBot) -> bool:
    if ALLOWED_USERS and user_id not in ALLOWED_USERS:
        bot.send_text(chat_id, "🚫 Access denied. Contact system administrator.")
        return False
    return True


def extract_attached_file(payload: dict):
    """Return (file_id, caption) of the first attachment in a message payload."""
    for part in payload.get("parts") or []:
        if not isinstance(part, dict):
            continue
        if part.get("type") in ("file", "image", "video", "audio", "voice"):
            inner = part.get("payload") or {}
            file_id = inner.get("fileId")
            if file_id:
                return file_id, inner.get("caption") or ""

    file_id = payload.get("fileId")
    if file_id:
        return file_id, payload.get("caption") or ""

    return None, ""


def async_prepare_file(bot: VKTeamsBot, chat_id: str, user_id: str, file_id: str):
    """Download an attached file, validate it and offer analysis modes."""
    bot.send_text(chat_id, "⏳ Downloading the attached file...")

    try:
        info = bot.get_file_info(file_id)
        if not info:
            bot.send_text(chat_id, "❌ Не удалось получить информацию о файле.", kb_main())
            USER_STATES.pop(user_id, None)
            return

        file_name = info.get("filename") or f"attachment_{file_id[:8]}"
        file_size = int(info.get("size") or 0)

        if file_size > MAX_FILE_SIZE_BYTES:
            bot.send_text(
                chat_id,
                f"❌ Файл слишком большой: `{format_bytes(file_size)}` "
                f"(лимит `{format_bytes(MAX_FILE_SIZE_BYTES)}`).",
                kb_main()
            )
            USER_STATES.pop(user_id, None)
            return

        content = bot.download_file(info["url"])

        if not is_text_like_file(file_name, content):
            bot.send_text(
                chat_id,
                f"❌ Файл `{file_name}` не похож на текстовый. "
                f"Поддерживаются: JSON, NDJSON, LOG, CSV, TXT, XML, YAML и др.",
                kb_main()
            )
            USER_STATES.pop(user_id, None)
            return

        file_text = decode_file_bytes(content)

        truncated = False
        if len(file_text) > MAX_FILE_TEXT_CHARS:
            file_text = file_text[:MAX_FILE_TEXT_CHARS]
            truncated = True

        tokens_count = count_tokens(file_text)

        state = USER_STATES.setdefault(user_id, {})
        state.update({
            "mode": "file",
            "step": "awaiting_file_mode",
            "file_text": file_text,
            "file_name": file_name,
            "file_size_str": format_bytes(file_size or len(content)),
            "file_tokens": tokens_count
        })

        note = "\n⚠️ Файл обрезан до первых 12 млн символов." if truncated else ""
        bot.send_text(
            chat_id,
            f"✅ Файл загружен.\n"
            f"📎 Имя: `{file_name}`\n"
            f"📁 Размер: `{format_bytes(file_size or len(content))}`\n"
            f"🧮 Tokens: `{tokens_count:,}`{note}\n\n"
            f"Выберите режим анализа файла с помощью ИИ:",
            kb_file_modes()
        )
    except Exception as e:
        bot.send_text(chat_id, f"❌ Ошибка при загрузке файла: {e}", kb_main())
        USER_STATES.pop(user_id, None)


def async_analyze_file(bot: VKTeamsBot, chat_id: str, user_id: str, custom_prompt: str = None):
    """Run AI analysis over the previously uploaded file."""
    state = USER_STATES.get(user_id, {})
    file_text = state.get("file_text")
    file_name = state.get("file_name", "attachment")
    file_size_str = state.get("file_size_str", "unknown")
    tokens_count = state.get("file_tokens", 0)

    if not file_text:
        bot.send_text(chat_id, "⚠️ Файл не найден или сессия истекла. Приложите файл заново.", kb_main())
        USER_STATES.pop(user_id, None)
        return

    USER_STATES[user_id]["step"] = "sending_ai"
    bot.send_text(
        chat_id,
        f"🤖 Отправляю файл `{file_name}` в ИИ на анализ "
        f"(`{tokens_count:,}` tokens). Пожалуйста, подождите..."
    )

    try:
        ai_response = query_router_ai_for_file(
            file_text=file_text,
            file_name=file_name,
            file_size=file_size_str,
            custom_prompt=custom_prompt
        )
        bot.send_text(chat_id, ai_response, kb_main())
    except Exception as e:
        bot.send_text(chat_id, f"❌ Ошибка при анализе файла: {e}", kb_main())
    finally:
        USER_STATES.pop(user_id, None)


def async_collect_and_process(bot: VKTeamsBot, chat_id: str, user_id: str, period_key: str):
    """Collect events from Wazuh node, apply jq filter, calculate tokens, and present decision menu."""
    state = USER_STATES.get(user_id, {})
    target_val = state.get("target_val")
    search_type = state.get("search_type", "user")
    delta, period_label = PERIOD_DELTAS[period_key]

    entity_label = "user" if search_type == "user" else "host"
    bot.send_text(chat_id, f"⏳ Collecting events for {entity_label} `{target_val}` from Wazuh ({period_label})...")

    end_date = datetime.now(timezone.utc)
    start_date = end_date - delta
    start_iso = start_date.isoformat()
    end_iso = end_date.isoformat()

    events = fetch_wazuh_events(target_val, search_type, start_iso, end_iso)

    if not events:
        bot.send_text(
            chat_id,
            f"⚠️ Events for {entity_label} `{target_val}` were not found on Wazuh for the selected period.",
            kb_main()
        )
        USER_STATES.pop(user_id, None)
        return

    raw_file = f"/tmp/{search_type}_{target_val}_report.json"
    final_file = "/tmp/final_report.json"

    try:
        with open(raw_file, "w", encoding="utf-8") as f:
            json.dump(events, f, ensure_ascii=False, indent=2)

        if not process_report_jq(raw_file, final_file):
            bot.send_text(chat_id, "❌ Failed to process report with jq utility.", kb_main())
            cleanup_all_reports(target_val, search_type)
            USER_STATES.pop(user_id, None)
            return

        size_bytes = os.path.getsize(final_file)
        size_kb = size_bytes / 1024.0

        with open(final_file, "r", encoding="utf-8") as f:
            processed_data = json.load(f)

        tokens_count = count_tokens(json.dumps(processed_data, ensure_ascii=False))

        USER_STATES[user_id]["step"] = "awaiting_ai_decision"
        USER_STATES[user_id]["period_label"] = period_label

        bot.send_text(
            chat_id,
            f"✅ Report generated from SIEM node.\n"
            f"📁 File size: `{size_kb:.2f} KB` (`{size_bytes}` bytes)\n"
            f"🧮 Tokens: `{tokens_count:,}`\n\n"
            f"Do you want to send this report to AI for analysis?",
            kb_ai_decision()
        )
    except Exception as e:
        bot.send_text(chat_id, f"❌ Error processing report: {e}", kb_main())
        cleanup_all_reports(target_val, search_type)
        USER_STATES.pop(user_id, None)


def async_send_to_ai(bot: VKTeamsBot, chat_id: str, user_id: str, custom_prompt: str = None):
    """Send processed final report to RouterAI and return intelligence report."""
    state = USER_STATES.get(user_id, {})
    target_val = state.get("target_val")
    search_type = state.get("search_type", "user")
    period_label = state.get("period_label")
    final_file = "/tmp/final_report.json"

    bot.send_text(chat_id, "🤖 Sending report to AI for SOC analysis. Please wait...")

    try:
        with open(final_file, "r", encoding="utf-8") as f:
            json_data = json.load(f)

        ai_response = query_router_ai(
            json_data=json_data,
            target_val=target_val,
            search_type=search_type,
            period_label=period_label,
            custom_prompt=custom_prompt
        )
        bot.send_text(chat_id, ai_response, kb_main())
    except Exception as e:
        bot.send_text(chat_id, f"❌ Error during AI analysis: {e}", kb_main())
    finally:
        cleanup_all_reports(target_val, search_type)
        USER_STATES.pop(user_id, None)


def on_new_message(bot: VKTeamsBot, payload: dict):
    chat = payload.get("chat", {})
    chat_id = chat.get("chatId")
    from_user = payload.get("from", {})
    user_id = from_user.get("userId", "unknown")
    text = (payload.get("text") or "").strip()

    if not chat_id or not _check_access(user_id, chat_id, bot):
        return

    # Handle explicit start/reset command
    if text.lower() in ("/start", "/reset", "start", "reset", "/help"):
        state = USER_STATES.pop(user_id, None)
        if state and state.get("target_val"):
            cleanup_all_reports(state["target_val"], state.get("search_type", "user"))
        else:
            cleanup_all_reports()
        bot.send_text(
            chat_id,
            "🤖 VK Teams SIEM Bot activated.\nSelect required activity type:",
            kb_main()
        )
        return

    state = USER_STATES.get(user_id)
    if state:
        step = state.get("step")

        # A file attached at any moment always starts the file-analysis flow
        spontaneous_file_id, _ = extract_attached_file(payload)
        if spontaneous_file_id and step not in ("file_downloading", "sending_ai"):
            USER_STATES[user_id] = {"mode": "file", "step": "file_downloading"}
            EXECUTOR.submit(async_prepare_file, bot, chat_id, user_id, spontaneous_file_id)
            return

        if step == "awaiting_file":
            bot.send_text(
                chat_id,
                "📎 Прикрепите файл к сообщению (скрепка → выбрать файл), "
                "чтобы я мог проанализировать его с помощью ИИ.",
                kb_file_modes()
            )
            return

        elif step == "awaiting_file_custom_prompt":
            if not text:
                bot.send_text(chat_id, "⚠️ Промпт не может быть пустым. Введите промпт для анализа файла:")
                return

            USER_STATES[user_id]["step"] = "sending_ai"
            EXECUTOR.submit(async_analyze_file, bot, chat_id, user_id, custom_prompt=text)
            return

        elif step in ("awaiting_username", "awaiting_hostname"):
            if not text:
                label = "Username" if step == "awaiting_username" else "Hostname"
                bot.send_text(chat_id, f"⚠️ {label} cannot be empty. Enter target {label.lower()}:")
                return

            search_type = state.get("search_type", "user")
            USER_STATES[user_id]["target_val"] = text
            USER_STATES[user_id]["step"] = "awaiting_period"

            label_name = "user" if search_type == "user" else "host"
            bot.send_text(
                chat_id,
                f"🎯 Target {label_name}: `{text}`\n⚙️ Select event collection period:",
                kb_periods()
            )
            return

        elif step == "awaiting_custom_prompt":
            if not text:
                bot.send_text(chat_id, "⚠️ Prompt text cannot be empty. Enter your custom prompt:")
                return

            USER_STATES[user_id]["step"] = "sending_ai"
            EXECUTOR.submit(async_send_to_ai, bot, chat_id, user_id, custom_prompt=text)
            return

    # No active state: a bare attached file also starts file analysis
    lone_file_id, _ = extract_attached_file(payload)
    if lone_file_id:
        USER_STATES[user_id] = {"mode": "file", "step": "file_downloading"}
        EXECUTOR.submit(async_prepare_file, bot, chat_id, user_id, lone_file_id)
        return

    bot.send_text(
        chat_id,
        "🤖 VK Teams SIEM Bot\nSelect required activity type:",
        kb_main()
    )


def on_callback(bot: VKTeamsBot, payload: dict):
    query_id = payload.get("queryId")
    callback_data = payload.get("callbackData", "")

    chat = payload.get("chat", {})
    if not chat:
        msg = payload.get("message", {})
        chat = msg.get("chat", {})
    chat_id = chat.get("chatId")

    from_user = payload.get("from", {})
    user_id = from_user.get("userId", "unknown")

    bot.answer_callback(query_id)

    if not chat_id or not _check_access(user_id, chat_id, bot):
        return

    if callback_data == "menu:main":
        state = USER_STATES.pop(user_id, None)
        if state and state.get("target_val"):
            cleanup_all_reports(state["target_val"], state.get("search_type", "user"))
        bot.send_text(chat_id, "🤖 Main Menu:\nSelect activity type:", kb_main())

    elif callback_data == "file:analyze":
        USER_STATES[user_id] = {"mode": "file", "step": "awaiting_file"}
        bot.send_text(
            chat_id,
            "📎 **Аналитика файла с помощью ИИ**\n\n"
            "Прикрепите файл к следующему сообщению (скрепка → файл).\n"
            "Поддерживаются текстовые форматы: JSON, NDJSON, LOG, CSV, TXT, XML, YAML и др.\n"
            f"Максимальный размер: `{format_bytes(MAX_FILE_SIZE_BYTES)}`.",
            kb_file_modes()
        )

    elif callback_data == "file_see_prompt":
        bot.send_text(
            chat_id,
            f"📄 **Default Prompt Template (FILE):**\n\n```\n{DEFAULT_FILE_PROMPT_TEMPLATE}\n```",
            kb_file_modes()
        )

    elif callback_data.startswith("file_run:"):
        mode = callback_data.split(":")[1]
        state = USER_STATES.get(user_id)
        if not state or state.get("mode") != "file" or not state.get("file_text"):
            bot.send_text(
                chat_id,
                "⚠️ Файл не загружен или сессия истекла. Прикрепите файл заново.",
                kb_main()
            )
            USER_STATES.pop(user_id, None)
            return

        if mode == "custom":
            USER_STATES[user_id]["step"] = "awaiting_file_custom_prompt"
            bot.send_text(
                chat_id,
                "✍️ Введите промпт для анализа файла (например: "
                "«Найди подозрительные события и оцени активность пользователя»):"
            )
        else:
            USER_STATES[user_id]["step"] = "sending_ai"
            EXECUTOR.submit(async_analyze_file, bot, chat_id, user_id)

    elif callback_data == "act:user_activity":
        USER_STATES[user_id] = {"search_type": "user"}
        bot.send_text(chat_id, "👤 User Activity Options:", kb_prompt_options("user"))

    elif callback_data == "act:host_activity":
        USER_STATES[user_id] = {"search_type": "host"}
        bot.send_text(chat_id, "💻 Host Activity Options:", kb_prompt_options("host"))

    elif callback_data.startswith("prompt_see:"):
        search_type = callback_data.split(":")[1]
        template = DEFAULT_USER_PROMPT_TEMPLATE if search_type == "user" else DEFAULT_HOST_PROMPT_TEMPLATE
        bot.send_text(
            chat_id,
            f"📄 **Default Prompt Template ({search_type.upper()}):**\n\n```\n{template}\n```",
            kb_prompt_options(search_type)
        )

    elif callback_data.startswith("prompt_run:"):
        search_type = callback_data.split(":")[1]
        step = "awaiting_username" if search_type == "user" else "awaiting_hostname"
        USER_STATES[user_id] = {
            "search_type": search_type,
            "prompt_mode": "default",
            "step": step
        }
        prompt_msg = "✏️ Enter target username for SIEM analysis:" if search_type == "user" else "💻 Enter target hostname for SIEM analysis (agent.name):"
        bot.send_text(chat_id, prompt_msg)

    elif callback_data.startswith("prompt_custom:"):
        search_type = callback_data.split(":")[1]
        step = "awaiting_username" if search_type == "user" else "awaiting_hostname"
        USER_STATES[user_id] = {
            "search_type": search_type,
            "prompt_mode": "custom",
            "step": step
        }
        prompt_msg = "✏️ Enter target username for SIEM analysis:" if search_type == "user" else "💻 Enter target hostname for SIEM analysis (agent.name):"
        bot.send_text(chat_id, prompt_msg)

    elif callback_data.startswith("period:"):
        period_key = callback_data.split(":")[1]
        state = USER_STATES.get(user_id)
        if not state or state.get("step") != "awaiting_period":
            bot.send_text(chat_id, "⚠️ Session expired. Please start over.", kb_main())
            return

        USER_STATES[user_id]["step"] = "processing"
        EXECUTOR.submit(async_collect_and_process, bot, chat_id, user_id, period_key)

    elif callback_data == "ai:cancel":
        state = USER_STATES.pop(user_id, None)
        if state and state.get("target_val"):
            cleanup_all_reports(state["target_val"], state.get("search_type", "user"))
        bot.send_text(chat_id, "🗑️ Report deleted.", kb_main())

    elif callback_data == "ai:send":
        state = USER_STATES.get(user_id)
        if not state or state.get("step") != "awaiting_ai_decision":
            bot.send_text(chat_id, "⚠️ Session expired.", kb_main())
            return

        prompt_mode = state.get("prompt_mode", "default")
        if prompt_mode == "custom":
            USER_STATES[user_id]["step"] = "awaiting_custom_prompt"
            bot.send_text(chat_id, "✍️ Enter your custom prompt for AI analysis:")
        else:
            USER_STATES[user_id]["step"] = "sending_ai"
            EXECUTOR.submit(async_send_to_ai, bot, chat_id, user_id)


# =============================================================================
# MAIN LOOP
# =============================================================================
def main():
    bot = VKTeamsBot(VK_TEAMS_TOKEN, VK_TEAMS_API_URL)
    print("🤖 SIEM Bot started successfully.")

    # Drain accumulated historical events on startup to prevent processing stale requests
    try:
        initial_resp = bot.get_events(poll_time=1)
        if initial_resp and initial_resp.get("events"):
            for ev in initial_resp["events"]:
                e_id = ev.get("eventId", 0)
                if e_id > bot.last_event_id:
                    bot.last_event_id = e_id
            print(f"🔄 Skipped {len(initial_resp['events'])} stale event(s). Last Event ID set to: {bot.last_event_id}")
    except Exception as e:
        print(f"⚠️ Stale event drain warning: {e}")

    while True:
        try:
            resp = bot.get_events(poll_time=30)
            if not resp or not resp.get("events"):
                continue

            for event in resp["events"]:
                event_id = event.get("eventId", 0)
                if event_id > bot.last_event_id:
                    bot.last_event_id = event_id

                event_type = event.get("type")
                payload = event.get("payload", {})

                if event_type == "newMessage":
                    on_new_message(bot, payload)
                elif event_type == "callbackQuery":
                    on_callback(bot, payload)

        except KeyboardInterrupt:
            print("\n🛑 Stopping SIEM Bot...")
            sys.exit(0)
        except Exception as e:
            print(f"❌ Polling loop error: {e}")
            time.sleep(5)


if __name__ == "__main__":
    main()

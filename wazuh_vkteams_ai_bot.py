#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VK Teams [Workspace] SIEM Bot — Single-Node OpenSearch Aggregator & AI Analyzer
===================================================================
"""

import json
import os
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
CHUNK_MAX_TOKENS = 800_000

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
    "🛡️ SOC ML: USER {target_val} Report\n\n"
    "📊 Events: {events_count}\n\n"
    "**Аналитический отчет SOC (Security Operations Center)**\n"
    "**Дата анализа:** {date_str}\n"
    "**Объект мониторинга:** Wazuh SIEM Node\n"
    "**Пользователь:** {target_val}\n"
    "**Временной диапазон:** {period_label}\n"
    "**Система защиты:** Wazuh OSSEC / KESL\n\n"
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
    "🛡️ SOC ML: HOST {target_val} Report\n\n"
    "📊 Events: {events_count}\n\n"
    "**Аналитический отчет SOC (Security Operations Center)**\n"
    "**Дата анализа:** {date_str}\n"
    "**Объект мониторинга:** Wazuh SIEM Node\n"
    "**Хост/Агент:** {target_val}\n"
    "**Временной диапазон:** {period_label}\n"
    "**Система защиты:** Wazuh OSSEC / KESL\n\n"
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


def send_raw_prompt_to_router_ai(prompt: str) -> str:
    """Send isolated payload to RouterAI API with type-safe response handling."""
    payload = {
        "model": AI_MODEL,
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 1000
    }
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {AI_KEY}"
    }

    try:
        response = requests.post(AI_URL, headers=headers, json=payload, timeout=120)
        if response.status_code == 200:
            result = response.json()
            choices = result.get("choices")
            if choices and isinstance(choices, list) and len(choices) > 0:
                message = choices[0].get("message", {})
                if isinstance(message, dict):
                    return message.get("content", "❌ Empty content returned by AI.")
            return "❌ Malformed response structure from RouterAI API."
        return f"❌ RouterAI API Error [{response.status_code}]: {response.text}"
    except Exception as e:
        return f"❌ Failed to reach RouterAI API: {e}"


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
        f"jq 'map(del(.agent.ip, .agent.id, .agent.name, .timestamp, .siem_node, "
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

    if total_tokens < TOKEN_THRESHOLD:
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
        """Send message with chunking support for large outputs."""
        chunk_size = 3900
        if len(text) <= chunk_size:
            params = {"chatId": chat_id, "text": text}
            if keyboard:
                params["inlineKeyboardMarkup"] = json.dumps(keyboard, ensure_ascii=False)
            return self._call("messages/sendText", params, use_post=True)

        for i in range(0, len(text), chunk_size):
            chunk = text[i:i + chunk_size]
            is_last = (i + chunk_size) >= len(text)
            params = {"chatId": chat_id, "text": chunk}
            if is_last and keyboard:
                params["inlineKeyboardMarkup"] = json.dumps(keyboard, ensure_ascii=False)
            self._call("messages/sendText", params, use_post=True)

    def answer_callback(self, query_id: str, text: str = None):
        params = {"queryId": query_id}
        if text:
            params["text"] = text[:200]
        return self._call("messages/answerCallbackQuery", params)


# =============================================================================
# INLINE KEYBOARDS
# =============================================================================
def kb_main():
    return [
        [{"text": "👤 User activity", "callbackData": "act:user_activity", "style": "primary"}],
        [{"text": "💻 Host activity", "callbackData": "act:host_activity", "style": "primary"}]
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

        if step in ("awaiting_username", "awaiting_hostname"):
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

import urllib.request
import urllib.parse
import collections
import socket
import time
import sys
import os
import threading
import base64
import re
import json
from concurrent.futures import ThreadPoolExecutor, as_completed

# ИСТОЧНИКИ НАДЁЖНО ЗАФИКСИРОВАНЫ СТРОГО ИЗ ВАШЕГО PDF
SOURCES = [
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"
]

VALID_PROTOCOLS = {"ss", "ssr", "vless", "trojan", "hysteria", "hy2", "hysteria2", "tuic"}

PROTOCOL_NAMES = {
    "ss": "SS", "ssr": "SSR", "vless": "Vless", "trojan": "Trojan",
    "hysteria": "Hysteria v1", "hysteria2": "Hy2", "hy2": "Hy2", "tuic": "Tuic"
}

TIMEOUT = 2.5 
GLOBAL_MAX_WORKERS = 350

HOST_STATUS_CACHE = {}
host_cache_lock = threading.Lock()

GEOIP_CACHE = {}
geoip_cache_lock = threading.Lock()

GLOBAL_WORKING_LIST = []
global_working_lock = threading.Lock()
INVALID_CONFIGS = collections.defaultdict(list)
stats = {}  
progress_lock = threading.Lock()

def clear_old_files():
    print("0. Инициализация и тотальная очистка окружения...")
    
    invalid_dir = "Invalid"
    if not os.path.exists(invalid_dir):
        os.makedirs(invalid_dir)
        print(f" -> Создана пустая директория: {invalid_dir}/")
    else:
        deleted_inv = 0
        for f_name in os.listdir(invalid_dir):
            f_path = os.path.join(invalid_dir, f_name)
            if os.path.isfile(f_path):
                try:
                    os.remove(f_path)
                    deleted_inv += 1
                except Exception: pass
        print(f" -> Директория {invalid_dir}/ полностью очищена. Удалено старых логов ошибок: {deleted_inv}")

    protocols_dir = "protocols"
    if not os.path.exists(protocols_dir):
        os.makedirs(protocols_dir)
        print(f" -> Создана пустая директория: {protocols_dir}/")
    else:
        deleted_proto = 0
        for f_name in os.listdir(protocols_dir):
            f_path = os.path.join(protocols_dir, f_name)
            if os.path.isfile(f_path):
                try:
                    os.remove(f_path)
                    deleted_proto += 1
                except Exception: pass
        print(f" -> Директория {protocols_dir}/ полностью очищена. Удалено старых подписок: {deleted_proto}")

    deleted_root = 0
    for item in os.listdir("."):
        if item.endswith(".txt") and os.path.isfile(item):
            try:
                os.remove(item)
                deleted_root += 1
            except Exception: pass
    print(f" -> Корневой каталог очищен от результатов прошлых сессий. Стерто *.txt файлов: {deleted_root}\n")

def fetch_source_data(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            raw_bytes = response.read()
            text_content = raw_bytes.decode('utf-8', errors='ignore').strip()
            
        if text_content and "://" not in text_content and not text_content.startswith("#"):
            try:
                padded_content = text_content + "=" * ((4 - len(text_content) % 4) % 4)
                decoded_bytes = base64.b64decode(padded_content)
                return decoded_bytes.decode('utf-8', errors='ignore')
            except Exception:
                pass
        return text_content
    except Exception as e:
        print(f" [!] Сбой загрузки источника {url}: ({e})")
        return ""
def check_is_usa_geoip(host):
    """Проверяет физическое расположение хоста через кэшируемый DNS/GeoIP запрос."""
    if not host:
        return False
    with geoip_cache_lock:
        if host in GEOIP_CACHE:
            return GEOIP_CACHE[host]
            
    is_usa = False
    try:
        ip = socket.gethostbyname(host)
        req = urllib.request.Request(f"http://ip-api.com{ip}", headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=2.5) as resp:
            data = json.loads(resp.read().decode('utf-8', errors='ignore'))
            if data.get("countryCode") == "US":
                is_usa = True
    except Exception:
        pass
        
    with geoip_cache_lock:
        GEOIP_CACHE[host] = is_usa
    return is_usa

def try_reconstruct_broken_config(broken_str):
    """Попытка восстановить рабочую конфигурацию из текстовых фрагментов Reality/TLS."""
    try:
        text = broken_str.strip().replace('"', '').replace('+', '')
        host_match = re.search(r'(?:host|sni)=([^&?\s#]+)', text, re.IGNORECASE)
        port_match = re.search(r'port=(\d+)', text, re.IGNORECASE)
        path_match = re.search(r'path=([^&?\s#]+)', text, re.IGNORECASE)
        pbk_match = re.search(r'pbk=([^&?\s#]+)', text, re.IGNORECASE)
        sid_match = re.search(r'sid=([^&?\s#]+)', text, re.IGNORECASE)
        
        server_address = host_match.group(1) if host_match else None
        if not server_address:
            domain_match = re.search(r'([a-zA-Z0-9.-]+\.[a-zA-Z]{2,6})', text)
            if domain_match and not any(x in text for x in ["User-Agent", "Mozilla", "AppleWebKit"]):
                server_address = domain_match.group(1)
                
        if not server_address:
            return None, "unknown"
            
        port = "443"
        if port_match:
            port = port_match.group(1)
        elif ":" in text:
            split_colon = text.split(":")[-1]
            digits = "".join(c for c in split_colon if c.isascii() and c.isdigit())
            if digits and (1 <= int(digits) <= 65535):
                port = digits

        dummy_uuid = "00000000-0000-0000-0000-000000000000"
        query_params = []
        query_params.append("type=ws" if "type=ws" in text or "ws" in text.lower() else "type=tcp")
        if pbk_match: query_params.append(f"pbk={pbk_match.group(1)}")
        if sid_match: query_params.append(f"sid={sid_match.group(1)}")
        
        sni = host_match.group(1) if host_match else server_address
        query_params.append(f"sni={sni}")
        
        if "reality" in text.lower() or pbk_match:
            query_params.append("security=reality")
        else:
            query_params.append("security=tls")
            
        if path_match: query_params.append(f"path={path_match.group(1)}")
        elif "path=/" in text: query_params.append("path=/")

        reconstructed_url = f"vless://{dummy_uuid}@{server_address}:{port}?" + "&".join(query_params) + "#Reconstructed_Reality"
        return reconstructed_url, "vless"
    except Exception:
        return None, "unknown"

def validate_and_fix_config(config_str):
    """Анализирует конфигурации на валидность, чистит хвосты и фильтрует брак."""
    cleaned = config_str.strip().replace(" ", "")
    if "://" not in cleaned:
        return try_reconstruct_broken_config(config_str)
        
    try:
        # УСТРАНЕН АТТРИБУТ-БАГ: split возвращает список, берем индекс [0]
        proto_part = cleaned.split("://")[0].strip().lower()
        if proto_part not in VALID_PROTOCOLS:
            return try_reconstruct_broken_config(config_str)
            
        target_proto = "hy2" if proto_part in ["hy2", "hysteria2"] else proto_part
        hash_part = ""
        url_main = cleaned
        if "#" in url_main:
            url_main, hash_part = url_main.split("#", 1)
            
        main_part = url_main.split("://")[-1]
        if "@" not in main_part:
            return try_reconstruct_broken_config(config_str)
            
        auth_part, server_part = main_part.split("@", 1)
        if not auth_part.strip():
            return try_reconstruct_broken_config(config_str)
            
        if target_proto == "vless":
            uuid_clean = auth_part.strip()
            uuid_regex = re.compile(r'^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$')
            if not uuid_regex.match(uuid_clean):
                auth_part = "00000000-0000-0000-0000-000000000000"

        params_part = ""
        if "?" in server_part:
            server_part, params_part = server_part.split("?", 1)
            
        if ":" not in server_part:
            return try_reconstruct_broken_config(config_str)
            
        host, port_str = server_part.split(":", 1)
        if "/" in port_str:
            port_str, _ = port_str.split("/", 1)
            
        port_digits = "".join(c for c in port_str if c.isascii() and c.isdigit())
        if not port_digits or not (1 <= int(port_digits) <= 65535):
            return try_reconstruct_broken_config(config_str)
            
        fixed_url = f"{proto_part}://{auth_part}@{host}:{port_digits}"
        if params_part: fixed_url += f"?{params_part}"
        if hash_part: fixed_url += f"#{hash_part}"
        else: fixed_url += "#Fixed_Config"
            
        return fixed_url, target_proto
    except Exception:
        return try_reconstruct_broken_config(config_str)

def parse_host_port(config_str):
    try:
        main_part = config_str.split("://")[-1]
        if "#" in main_part: main_part = main_part.split("#")[0]
        if "?" in main_part: main_part = main_part.split("?")[0]
        if "@" in main_part: server_part = main_part.split("@")[-1]
        else: server_part = main_part
        if "/" in server_part: server_part = server_part.split("/")[0]
        if ":" in server_part:
            parts = server_part.split(":")
            host = parts[0]
            port_val = "".join(c for c in parts[1] if c.isascii() and c.isdigit())
            if port_val:
                return host, int(port_val)
    except Exception:
        pass
    return None

def test_host_socket(host, port):
    sock = None
    start_time = time.time()
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        return int((time.time() - start_time) * 1000)
    except Exception:
        return None
    finally:
        if sock:
            try:
                sock.shutdown(socket.SHUT_RDWR)
                sock.close()
            except Exception: pass

def test_single_proxy(config_str):
    parsed = parse_host_port(config_str)
    if not parsed: return None, config_str
    host, port = parsed
    cache_key = f"{host}:{port}"
    with host_cache_lock:
        if cache_key in HOST_STATUS_CACHE:
            return HOST_STATUS_CACHE[cache_key], config_str
    ping_result = test_host_socket(host, port)
    with host_cache_lock: 
        HOST_STATUS_CACHE[cache_key] = ping_result
    return ping_result, config_str

def save_protocol_files(protocol):
    global stats, GLOBAL_WORKING_LIST
    p_data = stats[protocol]
    sorted_tuples = sorted(p_data["working"], key=lambda x: x[0])
    working_strings = [item[1] for item in sorted_tuples]
    with global_working_lock:
        GLOBAL_WORKING_LIST.extend(p_data["working"])
        
    display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
    for suffix, data_list in [("", p_data["full_list"]), ("_working", working_strings)]:
        if not data_list: continue
        filename = f"protocols/{protocol}{suffix}.txt"
        title_tag = f"Aggregated {display_name}" if suffix == "" else f"Sorted By Ping {display_name}"
        lines_to_write = [f"#profile-title: Nikita29a | {title_tag}", f"#profile-update-interval: 24", ""] + data_list
        with open(filename, "w", encoding="utf-8") as f: 
            f.write("\n".join(lines_to_write) + "\n")
            
    sys.stdout.write(f"[Финиш] {protocol.upper()} завершен! Живых (отсортировано): {len(working_strings)}\\{p_data['total']} -> protocols/ на диске.\n") 
    sys.stdout.flush()
def split_proxy_by_protocols():
    global stats, stop_logging, INVALID_CONFIGS, GLOBAL_WORKING_LIST
    clear_old_files()
    print("1. Запуск парсера сторонних репозиториев...")
    all_lines = []
    
    for url in SOURCES:
        print(f" -> Скачивание базы: {url}...")
        content = fetch_source_data(url)
        if content:
            content_normalized = content.replace(",", "\n").replace("|", "\n").replace(" ", "\n")
            for raw_line in content_normalized.splitlines():
                cleaned = raw_line.strip()
                if not cleaned: continue
                if cleaned.startswith("vmess://") or "vmess" in cleaned.lower(): continue
                if "=vless://" in cleaned: cleaned = cleaned.replace("=vless://", "=\nvless://")
                if "=ssr://" in cleaned: cleaned = cleaned.replace("=ssr://", "=\nssr://")
                if "=trojan://" in cleaned: cleaned = cleaned.replace("=trojan://", "=\ntrojan://")
                
                for split_line in cleaned.split("\n"):
                    cand = split_line.strip()
                    if cand: all_lines.append(cand)
                        
    print(f"\nВсего собрано сырых строк: {len(all_lines)}")
    raw_categorized = collections.defaultdict(list)
    reconstructed_count = 0
    
    for line in all_lines:
        fixed_link, proto_detected = validate_and_fix_config(line)
        if fixed_link:
            raw_categorized[proto_detected].append(fixed_link)
            if "Reconstructed" in fixed_link or "Fixed" in fixed_link: reconstructed_count += 1
        else:
            safe_proto = proto_detected if proto_detected in VALID_PROTOCOLS or proto_detected == "unknown" else "unknown"
            INVALID_CONFIGS[safe_proto].append(line)
            
    print(f" -> [Инфо] Восстановлено из фрагментов: {reconstructed_count} конфигураций.")
    print("\n[Диск] Сохранение отбракованных невалидных конфигураций...")
    all_invalid_pool = set()
    for proto, bad_list in INVALID_CONFIGS.items():
        if bad_list:
            unique_bad = list(set(bad_list))
            all_invalid_pool.update(unique_bad)
            inv_filename = f"Invalid/{proto}_invalid.txt"
            with open(inv_filename, "w", encoding="utf-8") as f: f.write("\n".join(unique_bad) + "\n")
            print(f" -> Создан отчет ошибок: {inv_filename} (строк: {len(unique_bad)})")

    if all_invalid_pool:
        all_inv_filename = "Invalid/all_invalid.txt"
        with open(all_inv_filename, "w", encoding="utf-8") as f: f.write("\n".join(sorted(list(all_invalid_pool))) + "\n")

    # УНИКАЛИЗАЦИЯ ВЫНЕСЕНА ИЗ ЦИКЛА ДЛЯ ИСКЛЮЧЕНИЯ ЗАВИСАНИЯ (KEYBOARDINTERRUPT)
    protocol_groups = {}
    all_valid_flat_list = []
    for proto, configs in raw_categorized.items():
        unique_configs = list(set(configs))
        protocol_groups[proto] = unique_configs
        all_valid_flat_list.extend(unique_configs)
        
    print("\n[Экспорт] Запуск гибридного Regex + GeoIP анализа для создания USA_ALL.txt...")
    usa_all_configs = []
    usa_pattern = re.compile(r'#.*?\b(us|usa|united[\s_]*states|🇺🇸)\b', re.IGNORECASE)
    
    def process_usa_all_check(cfg):
        if usa_pattern.search(cfg): return cfg
        parsed = parse_host_port(cfg)
        if parsed and check_is_usa_geoip(parsed[0]): return cfg
        return None

    with ThreadPoolExecutor(max_workers=GLOBAL_MAX_WORKERS) as geo_exec:
        geo_futures = [geo_exec.submit(process_usa_all_check, c) for c in all_valid_flat_list]
        for fut in as_completed(geo_futures):
            res = fut.result()
            if res: usa_all_configs.append(res)
            
    if usa_all_configs:
        usa_all_filename = "USA_ALL.txt"
        unique_usa_all = sorted(list(set(usa_all_configs)))
        usa_all_lines = [f"#profile-title: Nikita29a | USA Raw Aggregated Database", f"#profile-update-interval: 24", ""] + unique_usa_all
        with open(usa_all_filename, "w", encoding="utf-8") as f: f.write("\n".join(usa_all_lines) + "\n")
        print(f" -> [Диск] Создан файл: {usa_all_filename} (Найдено серверов США по GeoIP+Regex: {len(unique_usa_all)})")
    else:
        print(" -> [Инфо] В сырой базе не обнаружено серверов США.")
        
    print(f"\n2. Старт ОДНОВРЕМЕННОГО тестирования и сортировки по пингу ({GLOBAL_MAX_WORKERS} потоков)...") 
    for proto, configs in protocol_groups.items():
        stats[proto] = {"total": len(configs), "tested": 0, "working": [], "finished": False, "full_list": configs}
        sys.stdout.write(f"[Пул] Загружен {proto.upper()} | Итого валидных к проверке: {len(configs)}\n")
    sys.stdout.flush()
        
    interleaved_tasks = []
    max_len = max(len(configs) for configs in protocol_groups.values()) if protocol_groups else 0
    for i in range(max_len):
        for proto, configs in protocol_groups.items(): 
            if i < len(configs): interleaved_tasks.append((configs[i], proto))
                
    if not interleaved_tasks:
        print(" -> Остановка: Нет валидных прокси к проверке.")
        return

    stop_logging = False
    def logger_thread():
        last_time = time.time()
        while not stop_logging:
            time.sleep(0.5)
            if time.time() - last_time >= 5.0:
                with progress_lock:
                    log_lines = [f"{k.upper()}: {v['tested']}\\{v['total']}" for k, v in stats.items() if not v["finished"]]
                    if log_lines: sys.stdout.write(" -> Прогресс " + " | ".join(log_lines) + "\n"); sys.stdout.flush()
                last_time = time.time()
                
    logger_actor = threading.Thread(target=logger_thread); logger_actor.start()
    
    with ThreadPoolExecutor(max_workers=GLOBAL_MAX_WORKERS) as global_executor:
        future_to_proto = {global_executor.submit(test_single_proxy, c): p for c, p in interleaved_tasks} 
        for future in as_completed(future_to_proto):
            proto = future_to_proto[future]
            ping_ms, config_str = future.result()
            with progress_lock:
                stats[proto]["tested"] += 1
                if ping_ms is not None: stats[proto]["working"].append((ping_ms, config_str))
                if stats[proto]["tested"] == stats[proto]["total"] and not stats[proto]["finished"]: 
                    stats[proto]["finished"] = True; save_protocol_files(proto)
                    
    stop_logging = True; logger_actor.join()
    
    print("\n3. Создание общего объединенного списка с глобальной сортировкой...")
    if GLOBAL_WORKING_LIST:
        global_sorted = sorted(GLOBAL_WORKING_LIST, key=lambda x: x[0])
        all_working_strings = [item[1] for item in global_sorted]
        
        with open("all_working.txt", "w", encoding="utf-8") as f:
            f.write("\n".join([f"#profile-title: Nikita29a | Verified Working All Protocols", ""] + all_working_strings) + "\n")
        print(f" -> [Диск] Создан общий файл в корне: all_working.txt (активных: {len(all_working_strings)})") 
        
        with open("top1000_active.txt", "w", encoding="utf-8") as f:
            f.write("\n".join([f"#profile-title: Nikita29a | TOP-1000 Ultra Low Ping", ""] + all_working_strings[:1000]) + "\n")
        print(f" -> [Диск] Создан файл лучших конфигураций: top1000_active.txt")
        
        print(" -> Проверка GeoIP для создания USA_active.txt...")
        usa_active_strings = []
        with ThreadPoolExecutor(max_workers=GLOBAL_MAX_WORKERS) as geo_active_exec:
            active_futures = [geo_active_exec.submit(process_usa_all_check, c) for c in all_working_strings]
            for fut in as_completed(active_futures):
                res = fut.result()
                if res: usa_active_strings.append(res)
                
        usa_active_sorted = [c for c in all_working_strings if c in usa_active_strings]
        with open("USA_active.txt", "w", encoding="utf-8") as f:
            f.write("\n".join([f"#profile-title: Nikita29a | USA Region Active Only", ""] + usa_active_sorted) + "\n")
        print(f" -> [Диск] Создан файл США-региона: USA_active.txt (активных серверов США: {len(usa_active_sorted)})")
    else:
        print(" -> Живые прокси отсутствуют.")
    print("\n[Успех] Агрегатор полностью завершил работу!")

if __name__ == "__main__":
    split_proxy_by_protocols()

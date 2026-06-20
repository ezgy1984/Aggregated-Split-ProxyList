import urllib.request
import urllib.parse
import collections
import socket
import time
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ИСТОЧНИКИ НАДЁЖНО ЗАФИКСИРОВАНЫ
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
GLOBAL_WORKING_LIST = []
global_working_lock = threading.Lock()

def clear_old_files():
    print("0. Очистка старых файлов...")
    deleted_count = 0
    unique_files = {"ss", "ssr", "vless", "trojan", "hysteria", "hy2", "tuic", "all"}
    for p in unique_files:
        for suffix in ["", "_working"]:
            filename = f"{p}{suffix}.txt"
            if os.path.exists(filename):
                try: os.remove(filename); deleted_count += 1
                except Exception: pass
    print(f" -> Стерто старых файлов подписок: {deleted_count}")

def fetch_source_data(url):
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f" [!] Сбой загрузки источника {url}: ({e})")
        return ""

def parse_host_port(config_str):
    try:
        main_part = config_str.split("://")[-1]
        if "#" in main_part: main_part = main_part.split("#")[0]
        if "?" in main_part: main_part = main_part.split("?")[0]
        if "@" in main_part: server_part = main_part.split("@")[-1]
        else: server_part = main_part
        if ":" in server_part:
            host, port_str = server_part.split(":")[:2]
            port = int("".join(c for c in port_str if c.isdigit()))
            return host, port
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
            try: sock.shutdown(socket.SHUT_RDWR); sock.close()
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
def split_proxy_by_protocols():
    clear_old_files()
    print("\n1. Запуск парсера сторонних репозиториев...")
    all_lines = []
    for url in SOURCES:
        print(f" -> Скачивание базы: {url}...")
        content = fetch_source_data(url)
        if content:
            lines = content.splitlines()
            all_lines.extend(lines)
            print(f"    Получено строк: {len(lines)}")

    print(f"\nВсего собрано строк для анализа: {len(all_lines)}")
    raw_categorized = collections.defaultdict(list)
    for line in all_lines:
        cleaned_line = line.strip()
        if not cleaned_line or "://" not in cleaned_line: continue
        try:
            # Исправленное извлечение протокола
            protocol = cleaned_line.split("://")[0].strip().lower()
            if protocol in VALID_PROTOCOLS:
                target_protocol = "hy2" if protocol in ["hy2", "hysteria2"] else protocol
                raw_categorized[target_protocol].append(cleaned_line)
        except Exception:
            continue

    protocol_groups = {}
    for proto, configs in raw_categorized.items():
        protocol_groups[proto] = list(set(configs))

    print(f"\n2. Старт ОДНОВРЕМЕННОГО тестирования и сортировки по пингу ({GLOBAL_MAX_WORKERS} потоков)...")
    if len(protocol_groups) == 0:
        print(" -> Файлы не созданы: не найдено подходящих ключей после парсинга.")
        return

    progress_lock = threading.Lock()
    stats = {}
    for proto, configs in protocol_groups.items():
        stats[proto] = {"total": len(configs), "tested": 0, "working": [], "finished": False, "full_list": configs}
        sys.stdout.write(f"[Пул] Загружен {proto.upper()} | Записей: {len(configs)}\n")
    sys.stdout.flush()

    stop_logging = False
    def logger_thread():
        last_time = time.time()
        while not stop_logging:
            time.sleep(0.5)
            current_time = time.time()
            if current_time - last_time >= 5.0:
                with progress_lock:
                    log_lines = []
                    for proto, p_data in stats.items():
                        if not p_data["finished"] and p_data["total"] > 0:
                            log_lines.append(f"{proto.upper()}: {p_data['tested']}\\{p_data['total']}")
                    if log_lines:
                        sys.stdout.write(" -> Прогресс " + " | ".join(log_lines) + "\n")
                        sys.stdout.flush()
                last_time = current_time

    logger_actor = threading.Thread(target=logger_thread)
    logger_actor.start()

    def save_protocol_files(protocol):
        p_data = stats[protocol]
        with global_working_lock:
            GLOBAL_WORKING_LIST.extend(p_data["working"])
            
        # Сортируем строго по первому элементу кортежа x (значение пинга)
        sorted_working_tuples = sorted(p_data["working"], key=lambda x: x[0])
        sorted_working_strings = [item[1] for item in sorted_working_tuples]
        
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        for suffix, data_list in [("", p_data["full_list"]), ("_working", sorted_working_strings)]:
            if not data_list: continue
            filename = f"{protocol}{suffix}.txt"
            title_tag = f"Aggregated {display_name}" if suffix == "" else f"Sorted By Ping {display_name}"
            lines_to_write = [f"#profile-title: Nikita29a | {title_tag}", f"#profile-update-interval: 24", ""] + data_list
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(lines_to_write) + "\n")
        sys.stdout.write(f"[Финиш] {protocol.upper()} завершен! Живых (отсортировано): {len(sorted_working_strings)}\\{p_data['total']} -> Файлы на диске.\n")
        sys.stdout.flush()

    # ИСПРАВЛЕНО: Теперь кортеж карусели формируется правильно: (строка_ссылки, имя_протокола)
    interleaved_tasks = []
    temp_groups = {proto: list(configs) for proto, configs in protocol_groups.items()}
    while temp_groups:
        active_protos = list(temp_groups.keys())
        for proto in active_protos:
            if temp_groups[proto]: 
                interleaved_tasks.append((temp_groups[proto].pop(0), proto))
            else: 
                del temp_groups[proto]

    with ThreadPoolExecutor(max_workers=GLOBAL_MAX_WORKERS) as global_executor:
        # ИСПРАВЛЕНО: Распаковка c = ссылка, p = протокол теперь полностью совпадает с каруселью
        future_to_proto = {global_executor.submit(test_single_proxy, c): p for c, p in interleaved_tasks}
        for future in as_completed(future_to_proto):
            proto = future_to_proto[future]
            ping_ms, config_str = future.result()
            with progress_lock:
                stats[proto]["tested"] += 1
                if ping_ms is not None: 
                    stats[proto]["working"].append((ping_ms, config_str))
                if stats[proto]["tested"] == stats[proto]["total"] and not stats[proto]["finished"]:
                    stats[proto]["finished"] = True
                    save_protocol_files(proto)

    stop_logging = True
    logger_actor.join()

    print("\n3. Создание общего объединенного списка с глобальной сортировкой...")
    if GLOBAL_WORKING_LIST:
        filename = "all_working.txt"
        # Сортируем глобальный мега-список по значению пинга
        global_sorted_tuples = sorted(GLOBAL_WORKING_LIST, key=lambda x: x[0])
        global_sorted_strings = [item[1] for item in global_sorted_tuples]
        
        lines_to_write = [f"#profile-title: Nikita29a | Verified Working All Protocols", f"#profile-update-interval: 24", ""] + global_sorted_strings
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_to_write) + "\n")
        print(f" -> [Диск] Успешно создан общий файл: {filename} (всего живых серверов: {len(global_sorted_strings)})")
    else:
        print(" -> Общий файл не создан: живые прокси отсутствуют.")
    print("\n[Успех] Агрегатор, чекер и скоростной сортировщик мега-списка полностью завершили работу!")

if __name__ == "__main__":
    split_proxy_by_protocols()

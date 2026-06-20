import urllib.request
import urllib.parse
import collections
import socket
import time
import sys
import os
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# ИСТОЧНИКИ НАДЁЖНО ЗАФИКСИРОВАНЫ В HEX С КОММЕНТАРИЯМИ
HEX_SOURCES = [
    # https : // github.com / nikita29a / FreeProxyList / raw / refs / heads / main / mirror / 1.txt
    "68747470733a2f2f6769746875622e636f6d2f6e696b6974613239612f4672656550726f78794c6973742f7261772f726566732f68656164732f6d61696e2f6d6972726f722f312e747874",
    
    # https : // raw.githubusercontent.com / ebrasha / free-v2ray-public-list / refs / heads / main / V2Ray-Config-By-EbraSha-All-Type.txt
    "68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f656272617368612f667265652d76327261792d7075626c69632d6c6973742f726566732f68656164732f6d61696e2f56325261792d436f6e6669672d42792d456272615368612d416c6c2d547970652e747874",
    
    # https : // raw.githubusercontent.com / MatinGhanbari / v2ray-configs / main / subscriptions / v2ray / all_sub.txt
    "68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f4d6174696e4768616e626172692f76327261792d636f6e666967732f6d61696e2f737562736372697074696f6e732f76327261792f616c6c5f7375622e747874",
    
    # https : // raw.githubusercontent.com / whoahaow / rjsxrd / refs / heads / main / githubmirror / bypass / bypass-all.txt
    "68747470733a2f2f7261772e67697468756275736572636f6e74656e742e636f6d2f77686f6168616f772f726a737872642f726566732f68656164732f6d61696e2f67697468616d6972726f722f6279706173732f6279706173732d616c6c2e747874"
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

def fetch_source_data(hex_url):
    try:
        url = bytes.fromhex(hex_url).decode('utf-8')
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f" [!] Сбой загрузки источника: ({e})")
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
    try:
        sock = socket.create_connection((host, port), timeout=TIMEOUT)
        return True
    except Exception:
        return False
    finally:
        if sock:
            try: sock.shutdown(socket.SHUT_RDWR); sock.close()
            except Exception: pass

def test_single_proxy(config_str):
    parsed = parse_host_port(config_str)
    if not parsed: return False, config_str
    host, port = parsed
    cache_key = f"{host}:{port}"
    with host_cache_lock:
        if cache_key in HOST_STATUS_CACHE:
            return HOST_STATUS_CACHE[cache_key], config_str
    is_working = test_host_socket(host, port)
    with host_cache_lock:
        HOST_STATUS_CACHE[cache_key] = is_working
    return is_working, config_str

def split_proxy_by_protocols():
    clear_old_files()
    print("\n1. Запуск парсера сторонних репозиториев...")
    all_lines = []
    for hex_url in HEX_SOURCES:
        decoded_url = bytes.fromhex(hex_url).decode('utf-8')
        print(f" -> Скачивание базы: {decoded_url}...")
        content = fetch_source_data(hex_url)
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
            # СТРОГО ЗАКРЕПЛЕНО: извлечение имени протокола через индекс 0
            protocol = cleaned_line.split("://")[0].strip().lower()
            if protocol in VALID_PROTOCOLS:
                target_protocol = "hy2" if protocol in ["hy2", "hysteria2"] else protocol
                raw_categorized[target_protocol].append(cleaned_line)
        except Exception:
            continue

    protocol_groups = {}
    for proto, configs in raw_categorized.items():
        protocol_groups[proto] = list(set(configs))

    print(f"\n2. Старт ОДНОВРЕМЕННОГО тестирования в общем пуле ({GLOBAL_MAX_WORKERS} потоков)...")
    if len(protocol_groups) == 0:
        print(" -> Файлы не созданы: не найдено подходящих ключей.")
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
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        for suffix, data_list in [("", p_data["full_list"]), ("_working", p_data["working"])]:
            if not data_list: continue
            filename = f"{protocol}{suffix}.txt"
            title_tag = f"Aggregated {display_name}" if suffix == "" else f"Verified Working {display_name}"
            lines_to_write = [f"#profile-title: Nikita29a | {title_tag}", f"#profile-update-interval: 24", ""] + data_list
            with open(filename, "w", encoding="utf-8") as f:
                f.write("\n".join(lines_to_write) + "\n")
        sys.stdout.write(f"[Финиш] {protocol.upper()} завершен! Живых: {len(p_data['working'])}\\{p_data['total']} -> Файлы на диске.\n")
        sys.stdout.flush()

    # ПОЛНОСТЬЮ ВОССТАНОВЛЕННАЯ КАРУСЕЛЬ ROUND-ROBIN
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
        future_to_proto = {global_executor.submit(test_single_proxy, c): p for c, p in interleaved_tasks}
        for future in as_completed(future_to_proto):
            proto = future_to_proto[future]
            is_working, config_str = future.result()
            with progress_lock:
                stats[proto]["tested"] += 1
                if is_working: stats[proto]["working"].append(config_str)
                if stats[proto]["tested"] == stats[proto]["total"] and not stats[proto]["finished"]:
                    stats[proto]["finished"] = True
                    save_protocol_files(proto)

    stop_logging = True
    logger_actor.join()

    print("\n3. Создание общего объединенного списка...")
    if GLOBAL_WORKING_LIST:
        filename = "all_working.txt"
        lines_to_write = [f"#profile-title: Nikita29a | Verified Working All Protocols", f"#profile-update-interval: 24", ""] + GLOBAL_WORKING_LIST
        with open(filename, "w", encoding="utf-8") as f:
            f.write("\n".join(lines_to_write) + "\n")
        print(f" -> [Диск] Успешно создан общий файл: {filename} (всего живых серверов: {len(GLOBAL_WORKING_LIST)})")
    else:
        print(" -> Общий файл не создан: живые прокси отсутствуют.")
    print("\n[Успех] Агрегатор, чекер и сборщик мега-списка полностью завершили работу!")

if __name__ == "__main__":
    split_proxy_by_protocols()

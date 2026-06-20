import urllib.request
import collections
import os

# Ваши актуальные и полностью рабочие источники из лога
SOURCES = [
    "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt",
    "https://raw.githubusercontent.com/ebrasha/free-v2ray-public-list/refs/heads/main/V2Ray-Config-By-EbraSha-All-Type.txt",
    "https://raw.githubusercontent.com/MatinGhanbari/v2ray-configs/main/subscriptions/v2ray/all_sub.txt",
    "https://raw.githubusercontent.com/whoahaow/rjsxrd/refs/heads/main/githubmirror/bypass/bypass-all.txt"
]

# Расширенный белый список протоколов
VALID_PROTOCOLS = {"ss", "ssr", "vless", "trojan", "hysteria", "hy2", "hysteria2", "tuic"}

# Словарь для форматирования имен протоколов в заголовках
PROTOCOL_NAMES = {
    "ss": "SS",
    "ssr": "SSR",
    "vless": "Vless",
    "trojan": "Trojan",
    "hysteria": "Hysteria v1",
    "hysteria2": "Hy2",
    "hy2": "Hy2",
    "tuic": "Tuic"
}

def clear_old_files():
    """Удаляет старые файлы конфигураций перед новым запуском."""
    print("0. Очистка старых файлов...")
    deleted_count = 0
    unique_files = {"ss", "ssr", "vless", "trojan", "hysteria", "hy2", "tuic"}
    for protocol in unique_files:
        filename = f"{protocol}.txt"
        if os.path.exists(filename):
            try:
                os.remove(filename)
                deleted_count += 1
            except Exception:
                pass
    print(f" -> Успешно удалено старых файлов: {deleted_count}")

def fetch_source_data(url):
    """Безопасно скачивает данные из одного источника с увеличенным таймаутом для больших баз."""
    try:
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
        # Увеличили таймаут до 30 сек, так как база ebrasha весит довольно много
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f" [!] Ошибка скачивания источника {url}: ({e})")
        return ""

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

    # Хранилище уникальных конфигураций (set() автоматически убирает дубликаты)
    categorized_proxies = collections.defaultdict(set)

    # Группировка, нормализация и фильтрация протоколов
    for line in all_lines:
        cleaned_line = line.strip()
        if not cleaned_line or "://" not in cleaned_line:
            continue
        
        try:
            # ИСПРАВЛЕНО: берем [0] элемент списка (строку) перед вызовом методов .strip().lower()
            protocol = cleaned_line.split("://")[0].strip().lower()
            
            if protocol in VALID_PROTOCOLS:
                # Нормализация групп: сливаем hysteria2 и hy2 в один файл hy2.txt
                if protocol in ["hy2", "hysteria2"]:
                    target_protocol = "hy2"
                else:
                    target_protocol = protocol
                
                # Добавляем в множество (дубликаты отсекаются на лету)
                categorized_proxies[target_protocol].add(cleaned_line)
        except Exception:
            continue

    print("\n2. Сохранение новых объединенных файлов для NekoBox:")
    
    if not categorized_proxies:
        print(" -> Файлы не созданы: не найдено ни одного подходящего ключа.")
        return

    for protocol, configs_set in categorized_proxies.items():
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        filename = f"{protocol}.txt"
        
        configs_list = list(configs_set)
        
        # Спецификация формата подписок под NekoBox / NekoRay
        lines_to_write = [
            f"#profile-title: Ezgy's | Aggregated {display_name}",
            f"#profile-update-interval: 24",
            "" 
        ] + configs_list
        
        file_content = "\n".join(lines_to_write) + "\n"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f" -> Создан файл: {os.path.abspath(filename)} (Уникальных ключей: {len(configs_list)})")

    print("\n[Успех] Скрипт-агрегатор полностью отработал. Файлы созданы!")

if __name__ == "__main__":
    split_proxy_by_protocols()

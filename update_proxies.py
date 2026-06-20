import urllib.request
import collections
import os

# ССЫЛКА ЗАКРЕПЛЕНА И НЕ БУДЕТ МЕНЯТЬСЯ
URL = "https://github.com/nikita29a/FreeProxyList/raw/refs/heads/main/mirror/1.txt"

# Белый список протоколов (Vmess намеренно исключен)
VALID_PROTOCOLS = {"ss", "vless", "trojan", "hy2", "hysteria2", "tuic"}

# Словарь для форматирования имен протоколов в заголовках файлов
PROTOCOL_NAMES = {
    "ss": "SS",
    "hysteria2": "Hy2",
    "hy2": "Hy2",
    "trojan": "Trojan",
    "vless": "Vless",
    "tuic": "Tuic"
}

def clear_old_files():
    """Удаляет старые файлы конфигураций перед новым запуском."""
    print("0. Очистка старых файлов...")
    deleted_count = 0
    for protocol in VALID_PROTOCOLS:
        filename = f"{protocol}.txt"
        if os.path.exists(filename):
            try:
                os.remove(filename)
                deleted_count += 1
            except Exception as e:
                print(f" Не удалось удалить {filename}: {e}")
    if deleted_count > 0:
        print(f" -> Успешно удалено старых файлов: {deleted_count}")
    else:
        print(" -> Старых файлов не обнаружено. Папка чиста.")

def split_proxy_by_protocols():
    # Очищаем рабочую директорию перед стартом
    clear_old_files()
    
    print("\n1. Скачивание актуального списка прокси...")
    try:
        req = urllib.request.Request(URL, headers={'User-Agent': 'Mozilla/5.0'})
        with urllib.request.urlopen(req) as response:
            content = response.read().decode('utf-8', errors='ignore')
    except Exception as e:
        print(f"Ошибка при скачивании файла: {e}")
        return

    lines = content.splitlines()
    categorized_proxies = collections.defaultdict(list)

    # Группировка строк по префиксу протокола
    for line in lines:
        cleaned_line = line.strip()
        if not cleaned_line:
            continue
        
        if "://" in cleaned_line:
            try:
                # Извлекаем протокол (все, что до ://) в нижнем регистре
                protocol = cleaned_line.split("://")[0].lower()
                
                # Проверяем наличие в белом списке (Vmess автоматически отсекается)
                if protocol in VALID_PROTOCOLS:
                    categorized_proxies[protocol].append(cleaned_line)
            except Exception:
                continue

    print("\n2. Сохранение новых файлов в открытом формате (как на Codeberg):")
    
    if not categorized_proxies:
        print(" -> Файлы не созданы: в скачанном тексте не обнаружено подходящих протоколов.")
        return

    for protocol, configs in categorized_proxies.items():
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        filename = f"{protocol}.txt"
        
        # Спецификация формата Hiddify: открытые заголовки без лишних пробелов, ссылки текстом
        lines_to_write = [
            f"#profile-title: Nikita29a | {display_name}",
            f"#profile-update-interval: 24",
            "" # Пустая строка для правильного разделения структуры
        ] + configs
        
        file_content = "\n".join(lines_to_write) + "\n"
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f" -> Создан файл: {os.path.abspath(filename)} (конфигураций: {len(configs)})")

    print("\nРазделение успешно завершено! Формат полностью совместим с Hiddify.")

if __name__ == "__main__":
    split_proxy_by_protocols()

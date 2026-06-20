import urllib.request
import collections
import base64
import os

# Прямая ссылка на сырой текстовый файл в репозитории nikita29a
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
                # Исправленный парсинг: извлекаем левую часть до :// и переводим в нижний регистр
                protocol = cleaned_line.split("://")[0].lower()
                
                # Берем только протоколы из разрешенного списка
                if protocol in VALID_PROTOCOLS:
                    categorized_proxies[protocol].append(cleaned_line)
            except Exception:
                continue

    # Сохранение результатов в отдельные .txt файлы
    print("\n2. Сохранение и кодирование файлов в Base64 для Hiddify:")
    
    if not categorized_proxies:
        print(" -> Файлы не созданы: в скачанном тексте не обнаружено подходящих протоколов.")
        return

    for protocol, configs in categorized_proxies.items():
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        filename = f"{protocol}.txt"
        
        # Формируем исходный открытый текст с вашим заголовком
        header = f"# profile-title: Nikita29a | {display_name}"
        raw_content = header + "\n" + "\n".join(configs) + "\n"
        
        # Переводим открытый текст в строку Base64 для 100% совместимости с Hiddify
        bytes_content = raw_content.encode('utf-8')
        base64_content = base64.b64encode(bytes_content).decode('utf-8')
        
        with open(filename, "w", encoding="utf-8") as f:
            f.write(base64_content)
            
        print(f" -> Создан файл: {os.path.abspath(filename)} (конфигураций: {len(configs)})")

    print("\nРазделение успешно завершено! Все файлы зашифрованы в Base64 и готовы для Hiddify.")

if __name__ == "__main__":
    split_proxy_by_protocols()

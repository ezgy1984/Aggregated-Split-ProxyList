import urllib.request
import collections
import os

# Ссылка на оригинальный файл в репозитории nikita29a
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

def split_proxy_by_protocols():
    print("Скачивание актуального списка прокси...")
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
            protocol = cleaned_line.split("://")[0].lower()
            # Берем только протоколы из разрешенного списка (Vmess сюда не попадет)
            if protocol in VALID_PROTOCOLS:
                categorized_proxies[protocol].append(cleaned_line)

    # Сохранение результатов в отдельные .txt файлы
    print("\nСохранение файлов:")
    for protocol, configs in categorized_proxies.items():
        display_name = PROTOCOL_NAMES.get(protocol, protocol.upper())
        filename = f"{protocol}.txt"

        # Формируем контент: заголовок на первой строке + конфигурации
        header = f"# profile-title: Nikita29a | {display_name}"
        file_content = header + "\n" + "\n".join(configs) + "\n"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(file_content)
        print(f" -> Создан файл: {os.path.abspath(filename)} (конфигураций: {len(configs)})")

    print("\nРазделение успешно завершено!")

if __name__ == "__main__":
    split_proxy_by_protocols()

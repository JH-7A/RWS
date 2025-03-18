"""
URL模块
"""


def load_urls_from_file(filename):

    try:
        with open(filename, 'r', encoding='utf-8') as f:
            urls = [line.strip() for line in f.readlines() if line.strip()]
        return urls
    except FileNotFoundError:
        print(f"错误: 文件 {filename} 未找到。")
        return []
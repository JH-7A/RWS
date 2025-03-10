"""
配置模块 - 处理配置文件的加载和解析
"""
import yaml
import sys


def load_config():

    try:
        with open('config.yaml', 'r', encoding='utf-8') as f:
            config = yaml.safe_load(f)
        return config
    except FileNotFoundError:
        print("错误: 找不到 config.yaml 配置文件。")
        sys.exit(1)
"""
日志模块 - 处理日志记录
"""
import os
import datetime


def check_and_create_logs_dir():

    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    return log_dir


def write_log(log_message):

    log_dir = check_and_create_logs_dir()
    log_filename = os.path.join(log_dir, f"{datetime.datetime.now().strftime('%Y-%m-%d')}.log")
    with open(log_filename, 'a', encoding='utf-8') as log_file:
        log_file.write(f"{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')} - {log_message}\n")
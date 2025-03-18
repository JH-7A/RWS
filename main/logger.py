"""
日志模块 - 处理日志记录
"""
import os
import datetime
import json


def check_and_create_logs_dir():

    log_dir = 'logs'
    if not os.path.exists(log_dir):
        os.makedirs(log_dir)
    return log_dir


def write_log(result):

    log_dir = check_and_create_logs_dir()
    log_filename = os.path.join(log_dir, f"{datetime.datetime.now().strftime('%Y-%m-%d')}.log")
    
    # 获取POC信息
    poc_info = result['poc'].get('info', {})
    poc_name = poc_info.get('name', 'Unknown')
    poc_severity = poc_info.get('severity', 'info')
    
    # 获取URL
    url = result['url']
    
    # 获取请求和响应信息
    requests_info = []
    
    # 检查是否有多个响应
    if 'responses' in result and result['responses']:
        for i, response in enumerate(result['responses']):
            if response:
                request_info = {
                    'method': response.request.method,
                    'url': response.request.url,
                    'status_code': response.status_code
                }
                requests_info.append(request_info)
    elif result['response']:
        request_info = {
            'method': result['response'].request.method,
            'url': result['response'].request.url,
            'status_code': result['response'].status_code
        }
        requests_info.append(request_info)
    
    # 构建日志消息
    log_data = {
        'timestamp': datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'url': url,
        'poc_name': poc_name,
        'severity': poc_severity,
        'result': result['match_result'],
        'requests': requests_info
    }
    
    # 写入日志文件
    with open(log_filename, 'a', encoding='utf-8') as log_file:
        log_file.write(f"{json.dumps(log_data, ensure_ascii=False)}\n")
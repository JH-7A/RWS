"""
POC模块 - 处理POC文件的加载和执行
"""
import os
import yaml
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


def get_product_types():
    poc_dir = 'poc'
    product_types = []
    if os.path.exists(poc_dir):
        for type_name in os.listdir(poc_dir):
            type_path = os.path.join(poc_dir, type_name)
            if os.path.isdir(type_path):
                product_types.append(type_name)
    return product_types


def get_products(product_type):
    poc_dir = 'poc'
    products = []
    type_path = os.path.join(poc_dir, product_type)
    if os.path.exists(type_path):
        for product_name in os.listdir(type_path):
            product_path = os.path.join(type_path, product_name)
            if os.path.isdir(product_path):
                products.append(product_name)
    return products


def load_poc_file(product_type, product_name):
    poc_dir = 'poc'  # POC文件的根目录
    product_dir = os.path.join(poc_dir, product_type, product_name)

    if not os.path.exists(product_dir):
        raise FileNotFoundError(f"产品 {product_name} 的POC目录不存在。")

    # 获取产品下所有漏洞类型目录
    vuln_types = {}
    for vuln_subdir in os.listdir(product_dir):
        vuln_subdir_path = os.path.join(product_dir, vuln_subdir)
        if os.path.isdir(vuln_subdir_path):
            vuln_types[vuln_subdir] = []
            # 遍历漏洞类型目录下的文件
            for vuln_file in os.listdir(vuln_subdir_path):
                if vuln_file.endswith('.yaml'):
                    vuln_types[vuln_subdir].append(os.path.join(vuln_subdir_path, vuln_file))

    return vuln_types


def execute_poc(poc, url, config):
    if 'http' not in poc:
        return f"POC 格式错误：缺少 'http' 配置 (URL: {url})"

    try:
        http_config = poc["http"][0]
        method = http_config.get("method", ["GET"])[0]  # 默认使用GET方法
        path = http_config["path"][0].replace("{{BaseURL}}", url)  # 替换 BaseURL

        # 获取可选参数，如果不存在则使用默认值
        body = http_config.get("body", [""])[0]  # 如果没有body，使用空字符串

        # 合并配置文件中的请求头和POC中的请求头
        headers = config.get('headers', {}).copy()  # 首先使用配置文件中的请求头
        if "Rheader" in http_config:
            # 添加POC中的请求头，如果有重复则覆盖配置文件中的值
            poc_headers = {
                header.split(":")[0].strip(): header.split(":")[1].strip()
                for header in http_config["Rheader"]
            }
            headers.update(poc_headers)

        # 设置代理
        proxies = {}
        if config.get('proxy'):
            proxies = {
                "http": config['proxy'].get('http'),
                "https": config['proxy'].get('https')
            }

        # 设置超时
        timeout = config.get('timeout', 10)  # 默认10秒

        # 根据HTTP方法发送请求
        if method.upper() == "POST":
            response = requests.post(
                path,
                data=body,
                headers=headers,
                proxies=proxies,
                verify=False,
                timeout=timeout
            )
        elif method.upper() == "GET":
            response = requests.get(
                path,
                params=body,
                headers=headers,
                proxies=proxies,
                verify=False,
                timeout=timeout
            )
        else:
            return f"不支持的HTTP方法 {method}"

        # 匹配响应内容和状态
        match_result = match_response(poc, response)
        return {"url": url, "match_result": match_result, "response": response, "poc": poc}

    except requests.exceptions.RequestException as e:
        return {"url": url, "match_result": f"请求执行错误: {str(e)}", "response": None, "poc": poc}
    except Exception as e:
        return {"url": url, "match_result": f"POC执行错误: {str(e)}", "response": None, "poc": poc}


def match_single_condition(matcher, response):
    if matcher["type"] == "word" and "body" in matcher["part"]:
        return all(word in response.text for word in matcher["words"])
    elif matcher["type"] == "status":
        return response.status_code in matcher["status"]
    return False


def match_response(poc, response):
    matchers = poc["http"][0].get("matchers", [])
    
    # 如果没有定义 condition，默认使用 or 逻辑
    condition = poc["http"][0].get("condition", "or").lower()
    
    if not matchers:
        return "没有定义匹配规则。"
    
    # 获取所有匹配结果
    match_results = [match_single_condition(matcher, response) for matcher in matchers]
    
    # 根据条件判断最终结果
    if condition == "and":
        final_result = all(match_results)
    else:  # or 或其他情况
        final_result = any(match_results)
    
    return "漏洞扫描成功！" if final_result else "漏洞扫描失败。"


def execute_scans_in_parallel(pocs, urls, config):
    results = []

    # 使用ThreadPoolExecutor来并行执行漏洞扫描
    with ThreadPoolExecutor(max_workers=config['threads']) as executor:
        futures = []

        for poc in pocs:
            for url in urls:
                futures.append(executor.submit(execute_poc, poc, url, config))

        # 等待所有线程完成并收集结果
        for future in as_completed(futures):
            result = future.result()
            results.append(result)

    return results


def get_vuln_types(selected_products):
    vuln_types = {}
    for product_type, product_name in selected_products:
        try:
            vuln_types[(product_type, product_name)] = load_poc_file(product_type, product_name)
        except FileNotFoundError:
            continue
    return vuln_types 
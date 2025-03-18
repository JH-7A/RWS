"""
POC模块 - 处理POC文件的加载和执行
"""
import os
import yaml
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import time


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


def execute_single_request(request_config, url, config):

    try:
        method = request_config.get("method", ["GET"])[0]  # 默认使用GET方法
        path = request_config["path"][0].replace("{{BaseURL}}", url)  # 替换 BaseURL

        # 获取可选参数，如果不存在则使用默认值
        body = request_config.get("body", [""])[0]  # 如果没有body，使用空字符串

        # 合并配置文件中的请求头和POC中的请求头
        headers = config.get('headers', {}).copy()  # 首先使用配置文件中的请求头
        if "RequestHeader" in request_config:
            # 添加POC中的请求头，如果有重复则覆盖配置文件中的值
            poc_headers = {
                header.split(":")[0].strip(): header.split(":")[1].strip()
                for header in request_config["RequestHeader"]
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

        # 记录请求开始时间
        start_time = time.time()

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
            return None, f"不支持的HTTP方法 {method}"

        # 计算响应时间（秒）
        response_time = time.time() - start_time
        # 将响应时间添加到响应对象中
        setattr(response, 'elapsed_s', response_time)

        return response, None

    except requests.exceptions.RequestException as e:
        return None, f"请求执行错误: {str(e)}"
    except Exception as e:
        return None, f"执行错误: {str(e)}"


def execute_poc(poc, url, config):

    if 'requests' not in poc:
        return {"url": url, "match_result": f"POC 格式错误：缺少 'requests' 配置", "response": None, "poc": poc}

    try:
        # 存储所有请求的响应
        responses = []
        errors = []

        # 执行每个请求
        for request_config in poc["requests"]:
            response, error = execute_single_request(request_config, url, config)
            if error:
                errors.append(error)
                continue
            responses.append(response)

        # 如果所有请求都失败了
        if not responses:
            error_msg = "; ".join(errors) if errors else "所有请求均失败"
            return {"url": url, "match_result": error_msg, "response": None, "poc": poc}

        # 匹配响应内容和状态
        match_result = match_response(poc, responses)
        return {
            "url": url, 
            "match_result": match_result, 
            "responses": responses,  # 返回所有响应
            "response": responses[0] if responses else None,  # 为了兼容性，保留单个response
            "poc": poc
        }

    except Exception as e:
        return {"url": url, "match_result": f"POC执行错误: {str(e)}", "response": None, "poc": poc}


def match_single_condition(matcher, response):

    if matcher["type"] == "word" and "part" in matcher and "body" in matcher["part"]:
        return all(word in response.text for word in matcher["words"])
    elif matcher["type"] == "status":
        return response.status_code in matcher["status"]
    elif matcher["type"] == "time":
        # 获取响应时间（秒）
        response_time = getattr(response, 'elapsed_s', 0)
        
        # 检查是否满足时间条件
        if "gt" in matcher:  # 大于
            return response_time > float(matcher["gt"])
        elif "lt" in matcher:  # 小于
            return response_time < float(matcher["lt"])
        elif "gte" in matcher:  # 大于等于
            return response_time >= float(matcher["gte"])
        elif "lte" in matcher:  # 小于等于
            return response_time <= float(matcher["lte"])
    return False


def match_response(poc, responses):

    all_match_results = []

    # 对每个请求进行匹配
    for i, request_config in enumerate(poc["requests"]):
        if i >= len(responses):  # 如果响应数量不足
            break

        matchers = request_config.get("matchers", [])
        if not matchers:
            continue

        # 获取当前请求的匹配结果
        match_results = [match_single_condition(matcher, responses[i]) for matcher in matchers]
        
        # 获取当前请求的条件
        condition = request_config.get("condition", "or").lower()
        
        # 根据条件判断当前请求的结果
        if condition == "and":
            request_result = all(match_results)
        else:  # or 或其他情况
            request_result = any(match_results)
            
        all_match_results.append(request_result)

    # 如果没有任何匹配结果
    if not all_match_results:
        return "没有定义匹配规则。"

    # 所有请求都必须匹配成功
    final_result = all(all_match_results)
    
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
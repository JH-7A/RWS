"""
菜单模块 - 处理菜单和用户交互
"""
import sys
import os
import yaml
import datetime
import pyfiglet

from .config import load_config
from .poc import get_product_types, get_products, get_vuln_types, execute_scans_in_parallel
from .url import load_urls_from_file
from .logger import write_log
from .report import initialize_html_report, update_html_report, finalize_html_report


def print_banner():

    ascii_art = pyfiglet.figlet_format("RWS", font="slant")
    print("*" * 60)
    print(ascii_art)
    print("                        Designed by JH-7A")
    print("-" * 60)


def select_product_types(product_types):

    while True:
        print("使用提示：\n请选择产品类型(输入 'exit' 退出)")
        print(f"可进行组合选择（如：1,2 或 all 选择所有类型）")
        print("输入 'cd ..' 可返回上一级")
        for idx, type_name in enumerate(product_types, 1):
            print(f"{idx}. {type_name}")

        type_choice = input("\n请输入产品类型编号: ")

        if type_choice.lower() == 'exit':
            print("退出程序。")
            sys.exit(0)

        if type_choice.lower() == 'cd ..':
            print("已经在最顶层，无法返回上一级。")
            continue

        if type_choice.lower() == 'all':
            return product_types

        try:
            type_choices = [int(x) for x in type_choice.split(',')]
            if any(choice < 1 or choice > len(product_types) for choice in type_choices):
                print("无效的选择，请重新选择。")
                continue
            return [product_types[i - 1] for i in type_choices]
        except ValueError:
            print("无效的输入，请输入数字或 'all' 或 'exit'。")
            continue


def handle_product_selection(product_choice, product_map):

    if product_choice.lower() == 'all':
        return product_map  # 直接返回所有产品

    try:
        product_choices = [int(x) for x in product_choice.split(',')]
        if any(choice < 1 or choice > len(product_map) for choice in product_choices):
            print("无效的选择，请重新选择。")
            return None
        return [product_map[i - 1] for i in product_choices]
    except ValueError:
        print("无效的输入，请输入数字或 'all' 或 'exit'。")
        return None


def handle_scanning(selected_pocs, config):

    while True:
        url_choice = input("\n请输入要扫描的URL（或者指定一个URL文件，如urls.txt）:")
        print("输入 'cd ..' 返回上一级")

        if url_choice.lower() == 'exit':
            sys.exit(0)

        if url_choice.lower() == 'cd ..':
            return True

        if url_choice.endswith('.txt'):
            urls = load_urls_from_file(url_choice)
            if not urls:
                print(f"错误: 未找到文件 {url_choice} 或文件为空，请重新输入文件名。")
                continue
        else:
            urls = [url_choice]

        # 执行扫描
        all_results = []
        vuln_results = []
        
        # 创建报告目录
        report_dir = 'report'
        if not os.path.exists(report_dir):
            os.makedirs(report_dir)
            
        # 生成唯一的报告文件名（基于时间戳）
        report_timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        report_file = os.path.join(report_dir, f"{report_timestamp}_scan_report.html")
        
        # 初始化HTML报告
        initialize_html_report(report_file)
        
        for poc_file in selected_pocs:
            with open(poc_file, 'r', encoding='utf-8') as file:
                poc = yaml.safe_load(file)
                
                # 单个POC的扫描结果
                results = execute_scans_in_parallel([poc], urls, config)
                all_results.extend(results)
                
                # 过滤出存在漏洞的结果
                current_vuln_results = [result for result in results
                                      if result.get('match_result') == "漏洞扫描成功！"]
                
                # 如果当前POC发现了漏洞
                if current_vuln_results:
                    vuln_results.extend(current_vuln_results)
                    
                    # 立即输出扫描结果并写入日志
                    for result in current_vuln_results:
                        print(f"发现漏洞: {result['url']} - {result['poc']['info'].get('name', 'Unknown') if 'info' in result['poc'] else 'Unknown'}")
                        write_log(result)
                    
                    # 立即更新HTML报告
                    update_html_report(report_file, current_vuln_results)
                    print(f"报告已更新: {report_file}")

        # 扫描完成后的总结
        if vuln_results:
            print(f"\n扫描完成! 共发现 {len(vuln_results)} 个漏洞，报告已保存到 {report_file}")
            # 完成HTML报告
            finalize_html_report(report_file)
        else:
            print("\n扫描完成! 未发现漏洞，不生成报告。")
            # 删除空报告
            if os.path.exists(report_file):
                os.remove(report_file)

        return False


def scan_menu():

    print_banner()
    
    config = load_config()
    while True:
        # 第一层：选择产品类型
        product_types = get_product_types()
        selected_types = select_product_types(product_types)
        if not selected_types:
            continue

        # 第二层：选择产品
        while True:  # 产品选择循环
            all_products = {}
            for product_type in selected_types:
                all_products[product_type] = get_products(product_type)

            product_map = []


            for product_type in selected_types:
                for product in all_products[product_type]:
                    product_map.append((product_type, product))
                    print(f"{len(product_map)}. [{product_type}] {product}")

            product_choice = input("\n请输入产品编号: ")

            if product_choice.lower() == 'exit':
                sys.exit(0)

            if product_choice.lower() == 'cd ..':
                break  # 返回上一级

            selected_products = handle_product_selection(product_choice, product_map)
            if not selected_products:
                continue

            # 如果选择了all，直接获取所有POC文件
            if product_choice.lower() == 'all':
                selected_pocs = []
                for product_type, product_name in selected_products:
                    try:
                        vuln_types = get_vuln_types([(product_type, product_name)])
                        for vuln_type in vuln_types.get((product_type, product_name), {}):
                            selected_pocs.extend(vuln_types[(product_type, product_name)][vuln_type])
                    except FileNotFoundError:
                        continue

                # 直接进入URL输入和扫描
                if handle_scanning(selected_pocs, config):
                    continue  # 返回产品选择
                break  # 完成扫描，回到最初
            else:
                # 第三层：选择漏洞类型
                vuln_types = get_vuln_types(selected_products)
                if not vuln_types:
                    continue

                while True:  # 漏洞类型选择循环


                    all_vuln_types = list(set(sum([list(v.keys()) for v in vuln_types.values()], [])))
                    for idx, vuln_type in enumerate(all_vuln_types, 1):
                        print(f"{idx}. {vuln_type}")

                    vuln_type_choice = input("\n请输入漏洞类型编号: ")

                    if vuln_type_choice.lower() == 'exit':
                        sys.exit(0)

                    if vuln_type_choice.lower() == 'cd ..':
                        break  # 返回产品选择

                    # 获取POC文件
                    poc_files = []
                    if vuln_type_choice.lower() == 'all':
                        # 直接获取所有POC文件并进入URL输入
                        for product_type, product_name in selected_products:
                            for vuln_type in vuln_types.get((product_type, product_name), {}):
                                poc_files.extend(vuln_types[(product_type, product_name)][vuln_type])
                        selected_pocs = poc_files
                        # 直接进入URL输入和扫描
                        if handle_scanning(selected_pocs, config):
                            continue  # 返回漏洞类型选择
                        break  # 完成扫描，返回产品选择
                    else:
                        try:
                            vuln_type_choices = [int(x) for x in vuln_type_choice.split(',')]
                            if any(choice < 1 or choice > len(all_vuln_types) for choice in vuln_type_choices):
                                print("无效的选择，请重新选择。")
                                continue

                            selected_vuln_types = [all_vuln_types[i - 1] for i in vuln_type_choices]
                            for product_type, product_name in selected_products:
                                for vuln_type in selected_vuln_types:
                                    if vuln_type in vuln_types.get((product_type, product_name), {}):
                                        poc_files.extend(vuln_types[(product_type, product_name)][vuln_type])
                        except ValueError:
                            print("无效的输入，请输入数字或 'all' 或 'exit'。")
                            continue

                        # 显示POC文件列表


                        for idx, poc_file in enumerate(poc_files, 1):
                            print(f"{idx}. {os.path.basename(poc_file)}")

                        while True:  # POC选择循环
                            poc_choice = input("\n请输入POC编号: ")

                            if poc_choice.lower() == 'exit':
                                sys.exit(0)

                            if poc_choice.lower() == 'cd ..':
                                break  # 返回漏洞类型选择

                            # 选择POC文件
                            if poc_choice.lower() == 'all':
                                selected_pocs = poc_files
                            else:
                                try:
                                    poc_choices = [int(x) for x in poc_choice.split(',')]
                                    if any(choice < 1 or choice > len(poc_files) for choice in poc_choices):
                                        print("无效的选择，请重新选择。")
                                        continue
                                    selected_pocs = [poc_files[i - 1] for i in poc_choices]
                                except ValueError:
                                    print("无效的输入，请输入数字或 'all' 或 'exit'。")
                                    continue

                            # 进入URL输入和扫描
                            if handle_scanning(selected_pocs, config):
                                continue  # 返回POC选择
                            break  # 完成扫描，返回漏洞类型选择

                        if poc_choice.lower() == 'cd ..':
                            continue  # 返回漏洞类型选择
                            break  # 完成扫描，返回产品选择

                if vuln_type_choice.lower() == 'cd ..':
                    continue  # 返回产品选择
                    break  # 完成所有操作，返回最外层

        if product_choice.lower() == 'cd ..':
            continue  # 返回到产品类型选择

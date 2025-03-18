"""
报告模块 - 处理报告生成和更新
"""
import os
import datetime
import json


def format_headers(headers):

    return '\n'.join(f"{k}: {v}" for k, v in headers.items())


def format_request(request):

    if not request:
        return "无请求信息"

    # 构建请求行
    method = request.method
    path = request.url.split('://')[-1].split('/', 1)[-1] or '/'
    protocol = "HTTP/1.1"

    # 获取主机名
    host = request.url.split('://')[-1].split('/', 1)[0]

    # 构建头部
    headers = dict(request.headers)
    if 'Host' not in headers:
        headers['Host'] = host

    # 构建请求内容
    formatted_request = f"{method} /{path} {protocol}\n"
    formatted_request += format_headers(headers)

    # 添加请求体
    if request.body:
        formatted_request += f"\n\n{request.body.decode() if isinstance(request.body, bytes) else request.body}"

    return formatted_request


def format_response(response):

    if not response:
        return "无响应信息"

    # 构建状态行
    protocol = "HTTP/1.1"
    status_code = response.status_code
    reason = response.reason or ''

    # 构建响应内容
    formatted_response = f"{protocol} {status_code} {reason}\n"
    formatted_response += format_headers(dict(response.headers))

    # 添加响应体
    if response.text:
        formatted_response += f"\n\n{response.text[:500]}"
        if len(response.text) > 500:
            formatted_response += "..."

    return formatted_response


def initialize_html_report(report_file):

    with open(report_file, 'w', encoding='utf-8') as f:
        f.write("""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width,initial-scale=1">
    <title>Vulnerability Scan Report</title>
    <script>
        var webVulns = [];
        var serviceVulns = [];
        var subdomains = [];
    </script>
    <style>
        body { 
            font-family: Arial, sans-serif; 
            margin: 0; 
            padding: 20px;
            background-color: #f5f5f5;
        }
        .vuln-item { 
            margin-bottom: 5px;
            background-color: white;
            border-radius: 4px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .vuln-header { 
            padding: 12px 15px;
            cursor: pointer;
            display: flex;
            align-items: center;
            font-size: 14px;
        }
        .vuln-header:hover {
            background-color: #f8f9fa;
        }
        .vuln-detail { 
            display: none;
            padding: 15px;
            border-top: 1px solid #eee;
        }
        .expand-icon {
            margin-right: 10px;
            font-size: 18px;
            width: 20px;
            text-align: center;
        }
        .request-response { 
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 4px;
            font-family: Monaco, Consolas, monospace;
            font-size: 12px;
            white-space: pre-wrap;
            margin: 10px 0;
        }
        .detail-item { 
            font-weight: bold;
            margin: 10px 0 5px;
            color: #666;
        }
        .vuln-info {
            display: flex;
            flex: 1;
            justify-content: space-between;
        }
        .vuln-url {
            color: #1a73e8;
        }
        .severity {
            padding: 2px 8px;
            border-radius: 3px;
            font-size: 12px;
            font-weight: bold;
        }
        .severity.high { background-color: #fce8e8; color: #d93026; }
        .severity.medium { background-color: #fff4e5; color: #e65100; }
        .severity.low { background-color: #e8f0fe; color: #1a73e8; }
        .severity.info { background-color: #e8f5e9; color: #1b5e20; }
        .report-info {
            background-color: white;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 20px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .report-title {
            font-size: 24px;
            margin-bottom: 10px;
        }
        .report-time {
            color: #666;
            font-size: 14px;
        }
        .report-summary {
            margin-top: 10px;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="report-info">
        <div class="report-title">漏洞扫描报告</div>
        <div class="report-time">开始时间: """ + datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S') + """</div>
        <div class="report-summary" id="report-summary">扫描进行中...</div>
    </div>
    <div id="vulns"></div>
    <script>
        function toggleDetail(index) {
            const detail = document.getElementById(`detail-${index}`);
            const header = detail.previousElementSibling;
            const icon = header.querySelector('.expand-icon');

            if (detail.style.display === 'block') {
                detail.style.display = 'none';
                icon.textContent = '+';
            } else {
                detail.style.display = 'block';
                icon.textContent = '-';
            }
        }
        
        function renderVulns() {
            const vulnContainer = document.getElementById('vulns');
            vulnContainer.innerHTML = '';
            
            webVulns.forEach((vuln, index) => {
                const vulnDiv = document.createElement('div');
                vulnDiv.className = 'vuln-item';

                const severityClass = vuln.severity.toLowerCase();
                vulnDiv.innerHTML = `
                    <div class="vuln-header" onclick="toggleDetail(${index})">
                        <span class="expand-icon">+</span>
                        <div class="vuln-info">
                            <span class="vuln-url">${vuln.target.url}</span>
                            <div>
                                <span class="severity ${severityClass}">${vuln.severity}</span>
                                <span style="margin-left: 10px">${vuln.plugin}</span>
                            </div>
                        </div>
                    </div>
                    <div class="vuln-detail" id="detail-${index}">
                        ${vuln.detail.snapshot.map(([req, resp]) => `
                            <div class="detail-item">Request:</div>
                            <div class="request-response">${req}</div>
                            <div class="detail-item">Response:</div>
                            <div class="request-response">${resp}</div>
                        `).join('')}
                    </div>
                `;

                vulnContainer.appendChild(vulnDiv);
            });
        }
    </script>
</body>
</html>
        """)


def update_html_report(report_file, results):

    # 读取现有报告内容
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 在</body>标签前插入新的漏洞数据
    insert_position = content.rfind('</body>')
    if insert_position == -1:
        return  # 如果找不到</body>标签，则退出
    
    # 构建要插入的漏洞数据脚本
    vuln_scripts = ""
    for result in results:
        # 处理多个响应的情况
        snapshots = []
        
        # 检查是否有多个响应
        if 'responses' in result and result['responses']:
            # 处理多个响应
            for response in result['responses']:
                if response:
                    snapshots.append([
                        format_request(response.request if response else None),
                        format_response(response)
                    ])
        else:
            # 兼容单个响应的情况
            snapshots.append([
                format_request(result['response'].request if result['response'] else None),
                format_response(result['response'])
            ])
        
        vuln_data = {
            "create_time": int(datetime.datetime.now().timestamp() * 1000),
            "detail": {
                "addr": result['url'],
                "payload": "",
                "snapshot": snapshots
            },
            "plugin": result['poc']['info'].get('name', 'Unknown') if 'info' in result['poc'] else 'Unknown',
            "target": {
                "url": result['url'],
                "params": []
            },
            "vuln_class": result['poc']['info'].get('type', '') if 'info' in result['poc'] else '',
            "severity": result['poc']['info'].get('severity', 'info') if 'info' in result['poc'] else 'info'
        }
        
        vuln_scripts += f"""
<script class='web-vulns'>
    webVulns.push({json.dumps(vuln_data, ensure_ascii=False)});
    renderVulns();
</script>
        """
    
    # 插入漏洞数据并保存
    new_content = content[:insert_position] + vuln_scripts + content[insert_position:]
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(new_content)


def finalize_html_report(report_file):

    # 读取现有报告内容
    with open(report_file, 'r', encoding='utf-8') as f:
        content = f.read()
    
    # 更新报告
    end_time = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    summary_update = f"""
<script>
    document.getElementById('report-summary').innerHTML = '扫描完成! 结束时间: {end_time}<br>共发现 ' + webVulns.length + ' 个漏洞';
</script>
    """
    
    # 在</body>标签前插入摘要更新脚本
    insert_position = content.rfind('</body>')
    if insert_position == -1:
        return  # 如果找不到</body>标签，则退出
    
    # 插入摘要更新并保存
    new_content = content[:insert_position] + summary_update + content[insert_position:]
    with open(report_file, 'w', encoding='utf-8') as f:
        f.write(new_content)


def generate_html_report(results):

    report_dir = 'report'
    if not os.path.exists(report_dir):
        os.makedirs(report_dir)

    report_file = os.path.join(
        report_dir,
        f"{datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_scan_report.html"
    )
    
    # 使用新的函数
    initialize_html_report(report_file)
    update_html_report(report_file, results)
    finalize_html_report(report_file)
    
    print(f"报告已保存到 {report_file}")
    return report_file
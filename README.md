# 漏洞扫描工具

一个用于扫描Web应用漏洞的命令行工具。RWS:Remote Weapon Station

## 项目结构

```
项目根目录/
├── poc/                # POC文件目录
│   └── 产品类型/
│       └── 产品名/
│           └── 漏洞类型/
│               └── poc文件.yaml
├── logs/              # 日志目录
├── report/            # 报告目录
├── main/              # 模块化代码目录
│   ├── __init__.py    # 包初始化文件
│   ├── config.py      # 配置模块
│   ├── poc.py         # POC处理模块
│   ├── logger.py      # 日志模块
│   ├── report.py      # 报告生成模块
│   ├── url.py         # URL处理模块
│   └── menu.py        # 菜单交互模块
├── config.yaml        # 配置文件
└── app.py             # 主程序
```

## 功能特点

- 支持多种产品类型和漏洞类型的扫描
- 实时生成漏洞报告，防止程序意外终止导致数据丢失
- 多线程扫描，提高扫描效率
- 交互式菜单，易于使用
- 详细的HTML报告，包含请求和响应信息

## 安装

1. 克隆仓库
2. 安装依赖：`pip install -r requirements.txt`

## 使用方法

1. 运行主程序：`python app.py`
2. 按照菜单提示选择产品类型、产品和漏洞类型
3. 输入目标URL或URL文件
4. 查看扫描结果和生成的报告

## 配置文件

配置文件`config.yaml`包含以下设置：

```yaml
# 线程数
threads: 10

# 超时时间（秒）
timeout: 10

# HTTP请求头
headers:
  User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36

# 代理设置（可选）
proxy:
  http: http://127.0.0.1:8080
  https: http://127.0.0.1:8080
```
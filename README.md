# 漏洞验证工具

一个用于漏洞验证的命令行工具。RWS:Remote Weapon Station
工具操作简单，各位师傅喜欢的话可以尝试用一用，就是要辛苦一下自己写poc了 :·)

## 法律与合规
- 本工具遵循 [Apache-2.0] 协议开源

- 禁止用于未经授权的网络扫描，违者须自行承担法律责任

- **漏洞扫描器免责声明**

  **1. 授权使用**
  本工具仅限用于**合法授权**的安全测试场景。使用者应确保已获得目标系统的明确书面授权。任何未经授权的扫描、渗透测试或攻击行为均属于非法活动，开发者对此类滥用行为不承担任何责任。

  **2. "按原样"原则**
  本软件以「现有状态」提供，**不提供任何明示或暗示的担保**，包括但不限于适销性、特定用途适用性、无漏洞或不侵权的保证。使用者需自行承担所有风险。

  **3. 结果可靠性**
  扫描结果可能存在误报/漏报，**不应视为系统安全的绝对结论**。使用者应通过人工验证所有发现，并自行判断结果的准确性。因依赖本工具数据导致的直接或间接损失，开发者概不负责。

  **4. 法律责任豁免**
  开发者及贡献者**不对任何因使用本工具导致的**数据泄露、服务中断、法律纠纷或经济损失承担责任，包括但不限于：

  - 违反当地网络安全法的行为
  - 扫描行为导致的系统崩溃
  - 测试数据残留引发的安全隐患

  **5. 合规要求**
  使用者须**严格遵守所在国家/地区的法律法规**，包括但不限于《网络安全法》《数据安全法》《个人信息保护法》等。跨境使用时需同时遵守目标服务器所在地的法律要求。

  **6. 禁止用途**
  严禁将本工具用于：

  - 未经授权的网络入侵
  - 关键基础设施的非法测试
  - 任何形式的网络攻击或破坏
  - 个人隐私数据的非法获取

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

- 支持多种产品类型和漏洞类型的扫描，可以自行创建目录，对产品以及版本进行分类
- 支持对多个请求的poc进行检测，支持对响应时间的检测
- 实时生成漏洞报告，防止程序意外终止导致数据丢失
- 多线程扫描，提高扫描效率
- 交互式菜单，易于使用
- 详细的HTML报告，包含请求和响应信息

## 安装

1. 克隆仓库
2. 安装依赖：`pip install -r requirements.txt`

## 使用方法

1. 运行主程序：`python app.py`
![image](https://github.com/user-attachments/assets/872b1ef5-940a-47d2-83b0-2f7fdba74b11)
2. 按照菜单提示选择产品类型、产品和漏洞类型（所有指令任意层级均能使用：cd .. exit 组合选择）
3. 输入目标URL或URL文件
4. 查看扫描结果和生成的报告（报告包含漏洞url，数据包信息，扫描时间，危害程度）
![image](https://github.com/user-attachments/assets/d986d357-cab7-452d-a800-d7d312157b36)

## 配置文件

配置文件`config.yaml`包含以下设置：

```yaml
# 线程数
threads: 10

# 超时时间（秒）
timeout: 10

# 代理设置（可选）
proxy:
  http: http://127.0.0.1:8080
  https: http://127.0.0.1:8080
```
## poc注意事项

1. 所有字段名称区分大小写
2. 冒号后必须有一个空格
3. 缩进使用两个空格
4. 字符串可以使用双引号或单引号
5. 多行文本使用`|`符号
6. 请求路径中的`{{BaseURL}}`会被替换为用户输入的URL
7. 每个请求必须至少有一个matcher
8. 所有请求都必须匹配成功，才认为漏洞存在
9. poc目录为示例poc

## 更新日志


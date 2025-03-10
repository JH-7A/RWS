#!/usr/bin/env python3

import sys
import urllib3

from main.menu import scan_menu


def main():

    # 禁用SSL警告
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    
    try:
        # 启动扫描菜单
        scan_menu()
    except KeyboardInterrupt:
        print("\n程序被用户中断")
        sys.exit(0)
    except Exception as e:
        print(f"\n程序发生错误: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main() 
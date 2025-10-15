# pysubdomain_scanner
python开发的子域名扫描工具

使用说明
安装依赖

pip install -r requirements.txt
基本用法

# 常见子域名扫描
python subdomain_scanner.py example.com

# 使用字典文件扫描
python subdomain_scanner.py example.com -w subdomains.txt

# 多线程扫描
python subdomain_scanner.py example.com -t 100

# 指定输出文件
python subdomain_scanner.py example.com -o results.txt
python subdomain_scanner.py example.com -o results.json
python subdomain_scanner.py example.com -o results.csv

# 指定扫描方法
python subdomain_scanner.py example.com --methods dns http


高级用法

# 组合使用所有选项
python subdomain_scanner.py example.com -w subdomains.txt -t 100 --timeout 10 -o results.json --methods dns http

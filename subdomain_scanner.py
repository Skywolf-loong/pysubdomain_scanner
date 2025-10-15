#!/usr/bin/env python3
"""
子域名扫描工具
支持多线程扫描、多种发现方式
"""

import argparse
import threading
import queue
import time
import sys
import os
from urllib.parse import urlparse
import socket
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import json
import csv
from datetime import datetime

class SubdomainScanner:
    def __init__(self, domain, threads=50, timeout=5, output=None):
        self.domain = domain.lower().strip()
        self.threads = threads
        self.timeout = timeout
        self.output = output
        self.found_subdomains = set()
        self.lock = threading.Lock()
        self.checked_count = 0
        self.start_time = time.time()
        
        # 设置DNS解析器
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = timeout
        self.resolver.lifetime = timeout
        
        # 输出文件设置
        self.output_handlers = []
        if output:
            if output.endswith('.json'):
                self.output_handlers.append(JSONOutput(output))
            elif output.endswith('.csv'):
                self.output_handlers.append(CSVOutput(output))
            else:
                self.output_handlers.append(TextOutput(output))

    def load_subdomains_from_file(self, wordlist_file):
        """从文件加载子域名字典"""
        subdomains = set()
        try:
            with open(wordlist_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    subdomain = line.strip()
                    if subdomain and not subdomain.startswith('#'):
                        subdomains.add(subdomain)
            print(f"[+] 已加载 {len(subdomains)} 个子域名")
            return list(subdomains)
        except FileNotFoundError:
            print(f"[-] 错误: 文件 {wordlist_file} 不存在")
            return []
        except Exception as e:
            print(f"[-] 读取文件错误: {e}")
            return []

    def dns_scan(self, subdomain):
        """DNS解析扫描"""
        full_domain = f"{subdomain}.{self.domain}"
        try:
            answers = self.resolver.resolve(full_domain, 'A')
            ips = [str(rdata) for rdata in answers]
            return full_domain, ips, "DNS"
        except:
            return None

    def http_scan(self, subdomain):
        """HTTP请求扫描"""
        full_domain = f"{subdomain}.{self.domain}"
        for protocol in ['https', 'http']:
            url = f"{protocol}://{full_domain}"
            try:
                response = requests.get(
                    url, 
                    timeout=self.timeout, 
                    verify=False,
                    allow_redirects=True
                )
                if response.status_code < 400:
                    return full_domain, [url], "HTTP"
            except:
                continue
        return None

    def certificate_scan(self, subdomain):
        """证书透明度扫描（简化版）"""
        # 这里可以实现证书透明度查询
        # 由于需要第三方API，这里留作扩展
        return None

    def check_subdomain(self, subdomain, methods=['dns', 'http']):
        """检查单个子域名"""
        result = None
        
        for method in methods:
            if method == 'dns':
                result = self.dns_scan(subdomain)
            elif method == 'http':
                result = self.http_scan(subdomain)
            elif method == 'cert':
                result = self.certificate_scan(subdomain)
            
            if result:
                break
        
        with self.lock:
            self.checked_count += 1
            if result:
                domain, ips, method = result
                self.found_subdomains.add(domain)
                status_msg = f"[+] 发现: {domain} (方法: {method})"
                print(status_msg)
                
                # 写入输出文件
                for handler in self.output_handlers:
                    handler.write(domain, ips, method)
                
                return domain
            
            # 进度显示
            if self.checked_count % 100 == 0:
                elapsed = time.time() - self.start_time
                print(f"[*] 已检查 {self.checked_count} 个子域名, 发现 {len(self.found_subdomains)} 个, 耗时: {elapsed:.2f}s")
            
            return None

    def scan_with_wordlist(self, wordlist_file, methods=['dns', 'http']):
        """使用字典文件进行扫描"""
        subdomains = self.load_subdomains_from_file(wordlist_file)
        if not subdomains:
            return
        
        print(f"[*] 开始扫描 {self.domain}, 使用 {len(subdomains)} 个子域名")
        print(f"[*] 线程数: {self.threads}, 超时: {self.timeout}s")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain, subdomain, methods): subdomain 
                for subdomain in subdomains
            }
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    continue

    def common_scan(self, methods=['dns', 'http']):
        """常见子域名扫描"""
        common_subdomains = [
            'www', 'mail', 'ftp', 'localhost', 'webmail', 'smtp', 'pop', 'ns1', 'webdisk',
            'ns2', 'cpanel', 'whm', 'autodiscover', 'autoconfig', 'ns', 'test', 'admin',
            'blog', 'dev', 'api', 'secure', 'vpn', 'mobile', 'shop', 'app', 'cdn', 'm',
            'email', 'portal', 'support', 'forum', 'news', 'media', 'static', 'docs',
            'store', 'shop', 'db', 'sql', 'backup', 'old', 'new', 'beta', 'staging',
            'mail2', 'test', 'live', 'search', 'images', 'img', 'download', 'uploads',
            'video', 'music', 'demo', 'help', 'kb', 'wiki', 'status', 'monitor',
            'payment', 'billing', 'invoice', 'secure', 'ssl', 'cdn', 'cloud', 'server',
            'serv', 'service', 'services', 'app', 'apps', 'office', 'remote', 'share',
            'shared', 'sharepoint', 'ftp', 'file', 'files', 'doc', 'docs', 'document',
            'map','yiyan','chat','baijiahao','ti','zhidao'
        ]
        
        print(f"[*] 开始常见子域名扫描，共 {len(common_subdomains)} 个")
        
        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = {
                executor.submit(self.check_subdomain, subdomain, methods): subdomain 
                for subdomain in common_subdomains
            }
            
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as e:
                    continue

    def generate_report(self):
        """生成扫描报告"""
        elapsed = time.time() - self.start_time
        print(f"\n[*] 扫描完成!")
        print(f"[*] 总耗时: {elapsed:.2f} 秒")
        print(f"[*] 检查总数: {self.checked_count}")
        print(f"[*] 发现子域名: {len(self.found_subdomains)}")
        
        if self.found_subdomains:
            print(f"\n[+] 发现的子域名:")
            for domain in sorted(self.found_subdomains):
                print(f"    {domain}")
        
        # 关闭输出文件
        for handler in self.output_handlers:
            handler.close()

# 输出处理类
class OutputHandler:
    def __init__(self, filename):
        self.filename = filename
        self.file = open(filename, 'w', encoding='utf-8')
        self.write_header()
    
    def write_header(self):
        pass
    
    def write(self, domain, ips, method):
        pass
    
    def close(self):
        self.file.close()

class TextOutput(OutputHandler):
    def write_header(self):
        self.file.write(f"# 子域名扫描报告\n")
        self.file.write(f"# 目标域名: \n")
        self.file.write(f"# 扫描时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        self.file.write(f"# \n")
    
    def write(self, domain, ips, method):
        self.file.write(f"{domain}\n")

class JSONOutput(OutputHandler):
    def write_header(self):
        self.file.write('{"scan_info": {"start_time": "' + 
                       datetime.now().isoformat() + 
                       '", "subdomains": [')
        self.first_entry = True
    
    def write(self, domain, ips, method):
        if not self.first_entry:
            self.file.write(',')
        self.file.write(json.dumps({
            'domain': domain,
            'ips': ips,
            'method': method,
            'discovery_time': datetime.now().isoformat()
        }))
        self.first_entry = False
    
    def close(self):
        self.file.write(']}')
        super().close()

class CSVOutput(OutputHandler):
    def write_header(self):
        self.file.write("domain,ips,method,discovery_time\n")
    
    def write(self, domain, ips, method):
        ips_str = ';'.join(ips)
        self.file.write(f'"{domain}","{ips_str}","{method}","{datetime.now().isoformat()}"\n')

def main():
    banner = """
    ███████╗██╗   ██╗██████╗ ██████╗  ██████╗ ███╗   ███╗ █████╗ ██╗███╗   ██╗
    ██╔════╝██║   ██║██╔══██╗██╔══██╗██╔═══██╗████╗ ████║██╔══██╗██║████╗  ██║
    ███████╗██║   ██║██║  ██║██║  ██║██║   ██║██╔████╔██║███████║██║██╔██╗ ██║
    ╚════██║██║   ██║██║  ██║██║  ██║██║   ██║██║╚██╔╝██║██╔══██║██║██║╚██╗██║
    ███████║╚██████╔╝██████╔╝██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║██║ ╚████║
    ╚══════╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝╚═╝  ╚═══╝
    
                       子域名扫描工具 v1.0 - 支持Windows
    """
    print(banner)
    
    parser = argparse.ArgumentParser(description='子域名扫描工具')
    parser.add_argument('domain', help='要扫描的目标域名 (例如: example.com)')
    parser.add_argument('-w', '--wordlist', help='子域名字典文件路径')
    parser.add_argument('-t', '--threads', type=int, default=50, help='线程数 (默认: 50)')
    parser.add_argument('--timeout', type=float, default=5, help='超时时间 (默认: 5秒)')
    parser.add_argument('-o', '--output', help='输出文件路径')
    parser.add_argument('--methods', nargs='+', default=['dns', 'http'], 
                       choices=['dns', 'http', 'cert'], 
                       help='扫描方法 (默认: dns http)')
    
    args = parser.parse_args()
    
    # 创建扫描器
    scanner = SubdomainScanner(
        domain=args.domain,
        threads=args.threads,
        timeout=args.timeout,
        output=args.output
    )
    
    try:
        if args.wordlist:
            # 使用字典扫描
            scanner.scan_with_wordlist(args.wordlist, args.methods)
        else:
            # 使用常见子域名扫描
            scanner.common_scan(args.methods)
        
        # 生成报告
        scanner.generate_report()
        
    except KeyboardInterrupt:
        print(f"\n[!] 用户中断扫描")
        scanner.generate_report()
    except Exception as e:
        print(f"[-] 扫描错误: {e}")
        scanner.generate_report()

if __name__ == "__main__":
    # 禁用SSL警告
    requests.packages.urllib3.disable_warnings()
    
    # 检查是否在Windows上运行
    if os.name == 'nt':
        print("[*] 检测到Windows系统")
    
    main()

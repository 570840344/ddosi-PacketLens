#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import sys
import ssl
import subprocess
import webbrowser

# 兼容 Python 2 和 Python 3 的 HTTP 服务器模块
if sys.version_info[0] == 3:
    from http.server import HTTPServer, SimpleHTTPRequestHandler
else:
    from BaseHTTPServer import HTTPServer
    from SimpleHTTPServer import SimpleHTTPRequestHandler

def create_self_signed_cert():
    """调用系统 openssl 命令生成自签名证书，兼容 Python 2/3"""
    print("🔐 正在生成自签名证书...")
    try:
        # 使用 openssl 命令行工具生成证书
        subprocess.check_call([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048',
            '-keyout', 'key.pem', '-out', 'cert.pem',
            '-days', '365', '-nodes', '-subj',
            '/C=CN/ST=Local/O=Python HTTPS Server/CN=localhost'
        ])
        print("✅ 证书已生成: cert.pem, key.pem")
        return True
    except subprocess.CalledProcessError:
        print("❌ 生成证书失败，请确保系统已安装 openssl 命令行工具。")
        return False
    except OSError:
        print("❌ 找不到 openssl 命令，请确保系统已安装并配置到环境变量中。")
        return False

def run_server(port=8443, directory="."):
    """启动 HTTPS 服务器"""
    os.chdir(directory)
    
    # 检查证书是否存在，不存在则自动生成
    cert_file = "cert.pem"
    key_file = "key.pem"
    
    if not (os.path.exists(cert_file) and os.path.exists(key_file)):
        if not create_self_signed_cert():
            sys.exit(1)
    
    # 创建服务器
    handler = SimpleHTTPRequestHandler
    httpd = HTTPServer(('0.0.0.0', port), handler)
    
    # 使用 SSL 上下文方式包装 socket (兼容 Python 2.7.9+ 和 Python 3.x)
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(cert_file, key_file)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    
    url = "https://localhost:%d" % port
    
    print("\n🚀 HTTPS 服务器已启动")
    print("📁 共享目录: " + os.path.abspath(directory))
    print("🔗 访问地址: " + url)
    print("⚠️  使用自签名证书，浏览器会提示不安全，请选择继续访问")
    print("按 Ctrl+C 停止服务器\n")
    
    # 启动后直接打开浏览器
    webbrowser.open(url)
    
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n👋 服务器已停止")

if __name__ == "__main__":
    port = 8443
    directory = "."
    
    # 支持命令行参数
    if len(sys.argv) > 1:
        try:
            port = int(sys.argv[1])
        except ValueError:
            directory = sys.argv[1]
    
    if len(sys.argv) > 2:
        directory = sys.argv[2]
    
    run_server(port, directory)
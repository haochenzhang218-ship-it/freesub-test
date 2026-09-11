#!/usr/bin/env python3
"""
节点质量检测脚本
读取 output/residential.txt，对每个节点进行实际连通测试，
通过代理获取真实出口 IP 并分类（Cloudflare / 数据中心 / ISP / 家宽）
输出 residential-check.csv 和 residential-check.md
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import socket
import ipaddress
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import tempfile
import shutil
import zipfile
import requests
import maxminddb
from concurrent.futures import ThreadPoolExecutor, as_completed

# 复用 main.py 中的常量与判断逻辑
CLOUDFLARE_IP_NETWORKS = [
    ipaddress.ip_network("173.245.48.0/20"),
    ipaddress.ip_network("103.21.244.0/22"),
    ipaddress.ip_network("103.22.200.0/22"),
    ipaddress.ip_network("103.31.4.0/22"),
    ipaddress.ip_network("141.101.64.0/18"),
    ipaddress.ip_network("108.162.192.0/18"),
    ipaddress.ip_network("190.93.240.0/20"),
    ipaddress.ip_network("188.114.96.0/20"),
    ipaddress.ip_network("197.234.240.0/22"),
    ipaddress.ip_network("198.41.128.0/17"),
    ipaddress.ip_network("162.158.0.0/15"),
    ipaddress.ip_network("104.16.0.0/13"),
    ipaddress.ip_network("104.24.0.0/14"),
    ipaddress.ip_network("172.64.0.0/13"),
    ipaddress.ip_network("131.0.72.0/22"),
]

DATACENTER_ASNS = {
    13335, 16509, 14618, 15169, 396982, 8075, 24940, 16276,
    14061, 31898, 63949, 45102, 132203, 20473, 60068, 55081,
    197540, 51167, 8560, 42708, 201814, 49981, 212238, 46652,
    141995, 200019, 136907, 39351, 9009, 174, 3356, 1299, 2914,
    199180, 202051, 62240, 49304, 34665, 209242, 219337, 44477,
    200651, 202685, 210644, 205628, 51852, 204544, 397373,
}

IDC_KEYWORDS = [
    "hosting", "datacenter", "data center", "cloud", "server", "vps",
    "dedicated", "compute", "colo", "digitalocean", "linode", "ovh",
    "hetzner", "choopa", "vultr", "alibaba", "tencent", "amazon", "aws",
    "google", "microsoft", "oracle", "fastly", "cloudflare", "akamai",
    "netgrid", "m247", "leaseweb", "contabo", "cogent", "zenlayer",
    "ucloud", "lagom", "ipvolume", "hostkey", "selectel", "quadranet",
    "buyvm", "play2go", "fzco",
]

RESIDENTIAL_WHITELIST_KEYWORDS = [
    "broadband", "dynamic", "pppoe", "cust", "dial", "user", "home",
    "residential", "ftth", "cable", "dsl", "consumer",
    "chunghwa", "hinet", "cht", "data communication business group",
    "taiwan fixed network", "kbro", "far eastone", "tfn",
    "hkbn", "hong kong broadband", "pccw", "hkt", "hgc", "smartone",
    "so-net", "kddi", "softbank", "ocn", "plala", "sk broadband",
    "korea telecom",
    "comcast", "charter", "at&t", "verizon", "spectrum", "cox",
    "vodafone", "deutsche telekom", "telekom", "orange", "bt-central",
    "virgin media",
]

INPUT_FILE = "output/residential.txt"
OUTPUT_CSV = "output/residential-check.csv"
OUTPUT_MD  = "output/residential-check.md"


# ─── 工具函数 ────────────────────────────────────────────────────────────────

def is_cloudflare_cdn_ip(ip_str):
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return any(ip_obj in net for net in CLOUDFLARE_IP_NETWORKS)
    except Exception:
        return False


def is_idc_ip(org_str):
    if not org_str:
        return False
    lower = org_str.lower()
    return any(kw in lower for kw in IDC_KEYWORDS)


def classify_ip_type(exit_ip, org_str, asn):
    """返回 (ip_type, detail)，ip_type: cloudflare/datacenter/isp/residential"""
    if is_cloudflare_cdn_ip(exit_ip):
        return "🔴 Cloudflare CDN", "入口/中转地址，非真实出口"

    if asn in DATACENTER_ASNS:
        return "🔴 数据中心 / 云服务商", f"ASN {asn}"

    if is_idc_ip(org_str):
        return "🔴 数据中心 / 机房", org_str

    # 民用白名单命中
    lower_org = (org_str or "").lower()
    for kw in RESIDENTIAL_WHITELIST_KEYWORDS:
        if kw in lower_org:
            return "🥇 优质家宽", org_str

    # 非数据中心且非云服务商 → ISP / 普通宽带
    return "🥈 ISP / 普通 IP", org_str or "未知"


def extract_node_info(node_str):
    """从原始链接解析协议、服务器、端口、UUID/密码"""
    info = {"raw": node_str, "proto": "", "server": "", "port": 0, "label": ""}
    try:
        if node_str.startswith("vless://"):
            m = re.search(r"vless://([^@]+)@([^:]+):(\d+)", node_str)
            if m:
                info.update({"proto": "vless", "server": m.group(2),
                             "port": int(m.group(3)), "label": m.group(1)[:8]})
        elif node_str.startswith("vmess://"):
            b64 = node_str[8:] + "=" * (-len(node_str[8:]) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            info.update({"proto": "vmess", "server": str(data.get("add", "")),
                         "port": int(data.get("port", 0)),
                         "label": data.get("ps", "")[:30]})
        elif node_str.startswith("ss://"):
            raw = node_str[5:].split("#")[0].strip()
            if ":" in raw:
                host_part = raw.split("@")[-1] if "@" in raw else raw
                if ":" in host_part:
                    srv, port_s = host_part.rsplit(":", 1)
                    info.update({"proto": "ss", "server": srv, "port": int(port_s),
                                 "label": srv[:20]})
        elif node_str.startswith("trojan://"):
            m = re.search(r"trojan://[^@]+@([^:]+):(\d+)", node_str)
            if m:
                info.update({"proto": "trojan", "server": m.group(1),
                             "port": int(m.group(2)), "label": "trojan"})
        elif node_str.startswith("hy2://") or node_str.startswith("hysteria2://"):
            prefix_len = len("hysteria2://") if node_str.startswith("hysteria2://") else len("hy2://")
            raw = node_str[prefix_len:].split("#")[0]
            m = re.search(r"([^@]+)@([^:/?#]+):(\d+)", raw)
            if m:
                info.update({"proto": "hysteria2", "server": m.group(2),
                             "port": int(m.group(3)), "label": "hy2"})
    except Exception:
        pass
    return info


def read_residential_nodes():
    """读取并解码 output/residential.txt，返回节点字符串列表"""
    if not os.path.exists(INPUT_FILE):
        print(f"[!] 输入文件不存在: {INPUT_FILE}")
        return []
    with open(INPUT_FILE, "r", encoding="utf-8") as f:
        raw = f.read().strip()
    try:
        decoded = base64.b64decode(raw).decode("utf-8", errors="ignore")
    except Exception:
        decoded = raw
    nodes = [l.strip() for l in decoded.split("\n") if l.strip()]
    print(f"[*] 读取到 {len(nodes)} 个节点")
    return nodes


def setup_xray():
    """确保 xray 二进制文件存在（仅 Linux 环境有效）"""
    if os.path.exists("xray"):
        return True
    if sys.platform != "linux":
        print("[!] 当前非 Linux 环境，无法下载 xray 二进制，跳过测活步骤")
        return False
    print("[*] 正在下载 Xray-core 测活内核...")
    url = "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip"
    try:
        resp = urllib.request.urlopen(url, timeout=60)
        with open("xray.zip", "wb") as f:
            f.write(resp.read())
        with zipfile.ZipFile("xray.zip", "r") as z:
            z.extract("xray")
        os.chmod("xray", 0o755)
        if os.path.exists("xray.zip"):
            os.remove("xray.zip")
        print("[+] xray 内核下载完成")
        return True
    except Exception as e:
        print(f"[!] xray 下载失败: {e}")
        return False


def setup_databases():
    """确保 MaxMind 数据库存在"""
    db_files = {"Country.mmdb": "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-Country.mmdb",
                "ASN.mmdb":   "https://github.com/P3TERX/GeoLite.mmdb/raw/download/GeoLite2-ASN.mmdb"}
    for fname, url in db_files.items():
        if not os.path.exists(fname):
            print(f"[*] 正在下载 {fname}...")
            try:
                resp = urllib.request.urlopen(url, timeout=60)
                with open(fname, "wb") as f:
                    f.write(resp.read())
                print(f"[+] {fname} 下载完成")
            except Exception as e:
                print(f"[!] {fname} 下载失败: {e}")
                return False
    return True


def test_node_xray(node_str, info, socks_port, timeout=12):
    """用 Xray 测试单个节点是否连通，返回 (success, delay_ms)"""
    proto = info["proto"]
    if proto == "hysteria2":
        return False, 0

    task_id = uuid.uuid4().hex
    cfg_path = f"xray_tmp_{task_id}.json"

    try:
        if proto == "vless":
            m = re.search(r"vless://([^@]+)@([^:]+):(\d+)\??(.*)", node_str)
            if not m:
                return False, 0
            uuid_str, server, port_s, query = m.groups()
            params = dict(re.findall(r"([^=&#]+)=([^&#]*)", query))
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": server, "port": int(port_s),
                                        "users": [{"id": uuid_str,
                                                   "encryption": params.get("encryption", "none")}]}]},
                "streamSettings": {"network": params.get("type", "tcp"),
                                   "security": params.get("security", "none")},
            }
            if params.get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get("sni", server),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", ""),
                    "fingerprint": params.get("fp", "chrome"),
                }
            elif params.get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get("sni", server), "allowInsecure": True}
            if params.get("type") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": urllib.parse.unquote(params.get("path", "/")),
                    "headers": {"Host": params.get("host", server)},
                }

        elif proto == "vmess":
            b64 = node_str[8:] + "=" * (-len(node_str[8:]) % 4)
            data = json.loads(base64.b64decode(b64).decode("utf-8", errors="ignore"))
            server, port, uuid_str = str(data.get("add", "")), int(data.get("port", 0)), str(data.get("id", ""))
            is_tls = data.get("tls") in ["tls", "1"]
            outbound = {
                "protocol": "vmess",
                "settings": {"vnext": [{"address": server, "port": port,
                                        "users": [{"id": uuid_str,
                                                   "alterId": int(data.get("aid", 0)),
                                                   "security": "auto"}]}]},
                "streamSettings": {"network": data.get("net", "tcp"),
                                   "security": "tls" if is_tls else "none"},
            }
            if is_tls:
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": str(data.get("host", server)).strip(), "allowInsecure": True}
            if data.get("net") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": data.get("path", "/"),
                    "headers": {"Host": str(data.get("host", server)).strip()},
                }

        elif proto == "ss":
            raw = node_str[5:].split("#")[0].strip()
            cipher, password, server, port = "", "", "", 0
            if "@" in raw:
                user_info, host_info = raw.split("@", 1)
                user_info += "=" * (-len(user_info) % 4)
                try:
                    dec = base64.b64decode(user_info).decode("utf-8", errors="ignore")
                    if ":" in dec:
                        cipher, password = dec.split(":", 1)
                except Exception:
                    pass
                if ":" in host_info:
                    server, port_s = host_info.split("/")[0].split("?")[0].split(":", 1)
                    port = int(port_s)
            outbound = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{"address": server, "port": port,
                                          "method": cipher or "chacha20-ietf-poly1305",
                                          "password": password}]},
            }

        elif proto == "trojan":
            m = re.search(r"trojan://([^@]+)@([^:]+):(\d+)\??(.*)", node_str)
            if not m:
                return False, 0
            password, server, port_s, query = m.groups()
            params = dict(re.findall(r"([^=&#]+)=([^&#]*)", query))
            outbound = {
                "protocol": "trojan",
                "settings": {"servers": [{"address": server, "port": int(port_s), "password": password}]},
                "streamSettings": {"network": params.get("type", "tcp"), "security": "tls",
                                   "tlsSettings": {"serverName": params.get("sni", server), "allowInsecure": True}},
            }
        else:
            return False, 0

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": socks_port, "listen": "127.0.0.1",
                          "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        }
        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        # Xray 是守护进程，用 Popen 后台运行，测完后 kill
        proc = subprocess.Popen(
            ["./xray", "run", "-config", cfg_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        time.sleep(1.5)  # 等待 xray 完成初始化并绑定 socks 端口

        start = time.time()
        try:
            req = urllib.request.Request(
                "http://ip-api.com/json/?fields=status,country,regionName,city,isp,org,asn,mobile,proxy,Hosting",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=10, proxy=urllib.request.ProxyHandler(
                {"http": f"http://127.0.0.1:{socks_port}", "https": f"http://127.0.0.1:{socks_port}"}
            )) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            delay = int((time.time() - start) * 1000)
            if data.get("status") == "success":
                result = (True, delay, data)
            else:
                result = (False, delay, {})
        except Exception:
            delay = int((time.time() - start) * 1000)
            result = (False, delay, {})
        finally:
            try:
                proc.terminate()
                proc.wait(timeout=3)
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
                return result
    except Exception:
        return False, 0, {}


def query_ip_info_via_proxy(socks_port):
    """通过指定 socks 代理查询当前出口 IP 信息"""
    try:
        proxy_handler = urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{socks_port}",
            "https": f"http://127.0.0.1:{socks_port}",
        })
        opener = urllib.request.build_opener(proxy_handler)
        req = urllib.request.Request(
            "http://ip-api.com/json/?fields=status,country,regionName,city,isp,org,asn,mobile,proxy,Hosting",
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"},
        )
        with opener.open(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception:
        return None


def get_rdns_host(ip):
    try:
        socket.setdefaulttimeout(1.0)
        return socket.gethostbyaddr(ip)[0].lower()
    except Exception:
        return ""


# ─── 主流程 ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  节点质量检测 — 基于真实出口 IP 的 residential 验证")
    print("=" * 60)

    # 1. 读取节点
    nodes = read_residential_nodes()
    if not nodes:
        print("[!] 没有可检测的节点，退出")
        sys.exit(0)

    # 2. 准备环境
    have_xray = setup_xray()
    have_db   = setup_databases()

    country_reader = None
    asn_reader     = None
    if have_db:
        try:
            country_reader = maxminddb.open_database("Country.mmdb")
            asn_reader     = maxminddb.open_database("ASN.mmdb")
        except Exception as e:
            print(f"[!] 数据库加载失败: {e}")

    # 3. 逐节点测试
    results = []
    total = len(nodes)

    for idx, node_str in enumerate(nodes, 1):
        info = extract_node_info(node_str)
        label = info["label"] or f"node-{idx}"
        server = info.get("server", "?")
        port   = info.get("port", 0)
        proto  = info.get("proto", "?")

        print(f"\n[{idx}/{total}] {label}  ({proto} {server}:{port})")

        # 3a. 快速判断服务器 IP 是否是 Cloudflare（前置拦截）
        is_cf_entry = False
        if server:
            try:
                is_cf_entry = is_cloudflare_cdn_ip(server)
            except Exception:
                pass
        if is_cf_entry:
            print(f"      服务器 IP {server} 属于 Cloudflare CDN 网段（入口），继续尝试穿透...")

        # 3b. Xray 连通测试
        success = False
        delay_ms = 0
        ip_data = None

        if have_xray:
            # 绑定一个空闲本地端口作为 SOCKS
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
                tmp.bind(("127.0.0.1", 0))
                socks_port = tmp.getsockname()[1]

            ok, dl, ip_data = test_node_xray(node_str, info, socks_port, timeout=15)
            success = ok
            delay_ms = dl
        else:
            print("      [跳过] Xray 不可用，无法进行连通测试")

        # 3c. 解析 IP 信息
        exit_ip        = ip_data.get("query", "")      if ip_data else ""
        exit_country   = ip_data.get("country", "")    if ip_data else ""
        exit_region    = ip_data.get("regionName", "") if ip_data else ""
        exit_city      = ip_data.get("city", "")       if ip_data else ""
        exit_isp       = ip_data.get("isp", "")        if ip_data else ""
        exit_org       = ip_data.get("org", "")        if ip_data else ""
        exit_asn_raw   = ip_data.get("asn", "")        if ip_data else ""
        is_proxy       = ip_data.get("proxy", False)   if ip_data else False
        is_mobile      = ip_data.get("mobile", False)  if ip_data else False

        # 解析 ASN 数字
        try:
            exit_asn = int(re.search(r"AS(\d+)", exit_asn_raw).group(1)) if exit_asn_raw else 0
        except Exception:
            exit_asn = 0

        # 3d. IP 类型判定
        if success and exit_ip:
            ip_type, ip_detail = classify_ip_type(exit_ip, exit_org, exit_asn)
        elif success:
            ip_type, ip_detail = "⚫ 无法获取出口 IP", "IP 查询未返回结果"
        else:
            ip_type, ip_detail = "⚫ 无法连接", ""

        # 综合评级
        if not success:
            grade = "⚫ 无法连接"
        elif ip_type.startswith("🔴"):
            grade = "🔴 数据中心 / Cloudflare / 不符合要求"
        elif "家宽" in ip_type:
            grade = "🥇 优质家宽"
        elif "ISP" in ip_type or "普通" in ip_type:
            grade = "🥈 优质 ISP / 原生 IP"
        else:
            grade = "🟡 可用但普通"

        result = {
            "index":        idx,
            "label":        label,
            "proto":        proto,
            "server":       server,
            "server_port":  port,
            "connect_ok":   "✓" if success else "✗",
            "delay_ms":     delay_ms,
            "exit_ip":      exit_ip or "(未获取)",
            "exit_country": exit_country,
            "exit_region":  exit_region,
            "exit_city":    exit_city,
            "exit_asn_num": exit_asn,
            "exit_asn_raw": exit_asn_raw,
            "exit_isp":     exit_isp or exit_org,
            "exit_org":     exit_org,
            "ip_type":      ip_type,
            "grade":        grade,
            "raw_node":     node_str,
        }
        results.append(result)

        # 打印摘要
        flag = f"[{idx}/{total}]"
        conn = "✓" if success else "✗"
        print(f"      {flag} {conn} {grade:30s} | 出口IP={exit_ip or 'N/A'} | 延迟={delay_ms}ms")

    # 关闭数据库
    if country_reader:
        country_reader.close()
    if asn_reader:
        asn_reader.close()

    # 4. 生成 CSV
    os.makedirs("output", exist_ok=True)
    csv_rows = [
        ["序号", "节点名称", "协议", "服务器地址", "服务器端口",
         "连通性", "延迟(ms)", "实际出口IP", "国家", "地区", "城市",
         "ASN编号", "ASN原始", "ISP/Organization",
         "IP类型", "综合评级"],
    ]
    for r in results:
        csv_rows.append([
            r["index"], r["label"], r["proto"], r["server"], r["server_port"],
            r["connect_ok"], r["delay_ms"], r["exit_ip"], r["exit_country"],
            r["exit_region"], r["exit_city"], r["exit_asn_num"], r["exit_asn_raw"],
            r["exit_isp"], r["ip_type"], r["grade"],
        ])
    try:
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "节点质量检查"
        for row in csv_rows:
            ws.append(row)
        # 样式：表头加粗
        for cell in ws[1]:
            cell.font = openpyxl.styles.Font(bold=True)
        wb.save(OUTPUT_CSV)
        print(f"\n[+] CSV 已保存: {OUTPUT_CSV}")
    except ImportError:
        # fallback: plain CSV
        with open(OUTPUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
            import csv
            writer = csv.writer(f)
            writer.writerows(csv_rows)
        print(f"\n[+] CSV 已保存 (无 openpyxl): {OUTPUT_CSV}")

    # 5. 生成 Markdown 报告
    total_n   = len(results)
    ok_n      = sum(1 for r in results if r["connect_ok"] == "✓")
    fail_n    = total_n - ok_n
    grade_cnt = {}
    for r in results:
        grade_cnt[r["grade"]] = grade_cnt.get(r["grade"], 0) + 1

    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())

    md_lines = [
        "# 📊 节点质量检测报告",
        "",
        f"> 生成时间：{now_str}  |  检测节点总数：{total_n}  |  成功连通：{ok_n}  |  失败：{fail_n}",
        "",
        "## 统计概览",
        "",
        "| 等级 | 数量 |",
        "|:---|---:|",
    ]
    for grade in ["🥇 优质家宽", "🥈 优质 ISP / 原生 IP", "🟡 可用但普通", "🔴 数据中心 / Cloudflare / 不符合要求", "⚫ 无法连接"]:
        cnt = grade_cnt.get(grade, 0)
        if cnt:
            md_lines.append(f"| {grade} | {cnt} |")

    md_lines += ["", "## 详细结果", ""]
    md_lines += [
        "| # | 名称 | 协议 | 服务器 | 出口IP | 国家 | ASN | ISP/Org | IP类型 | 评级 | 延迟 |",
        "|---|:---|:---|:---|:---|:---|:---|:---|:---|:---|---:|",
    ]
    for r in results:
        md_lines.append(
            f"| {r['index']} | {r['label'][:30]} | {r['proto']} | {r['server']}:{r['server_port']} "
            f"| {r['exit_ip'][:20]} | {r['exit_country']} | AS{r['exit_asn_num']} | "
            f"{r['exit_isp'][:25]} | {r['ip_type'][:20]} | {r['grade']} | {r['delay_ms']}ms |"
        )

    md_lines += [
        "",
        "## 说明",
        "",
        "- **🥇 优质家宽**：出口 IP 属于民用宽带 ASN，且命中住宅运营商白名单",
        "- **🥈 优质 ISP / 原生 IP**：非数据中心 ASN，归属普通 ISP，可能为原生 IP",
        "- **🟡 可用但普通**：可以连接但 IP 类型不明确",
        "- **🔴 数据中心 / Cloudflare**：命中 Cloudflare CDN 网段或已知数据中心 ASN",
        "- **⚫ 无法连接**：Xray 测活失败或超时",
        "",
        "> ⚠️ 本报告基于实际代理出口 IP + ASN 数据库重新验证，与原始 `residential.txt` 的分类结果相互独立。",
    ]

    md_content = "\n".join(md_lines)
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write(md_content)
    print(f"[+] Markdown 报告已保存: {OUTPUT_MD}")

    # 6. 汇总打印
    print("\n" + "=" * 60)
    print("  检测完成！")
    print(f"  总计：{total_n}  |  成功：{ok_n}  |  失败：{fail_n}")
    for grade in ["🥇 优质家宽", "🥈 优质 ISP / 原生 IP", "🟡 可用但普通", "🔴 数据中心 / Cloudflare", "⚫ 无法连接"]:
        cnt = grade_cnt.get(grade, 0)
        if cnt:
            print(f"  {grade}: {cnt}")
    print("=" * 60)


if __name__ == "__main__":
    main()

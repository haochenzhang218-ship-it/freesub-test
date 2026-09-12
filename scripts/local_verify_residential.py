#!/usr/bin/env python3
"""
本地节点可用性验证脚本
读取 output/residential-good.txt，在本机环境下逐个测试节点是否真正可用。
区分：TCP不通 / TLS握手失败 / 代理超时 / 完全可用
"""

import os
import re
import sys
import json
import time
import uuid
import base64
import socket
import ssl
import urllib.request
import urllib.parse
import subprocess
import zipfile

# 强制 stdout/stderr 使用 UTF-8（解决 Windows GBK 编码问题）
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

INPUT_FILE   = os.path.join("output", "residential-good.txt")
OUTPUT_CSV   = os.path.join("output", "residential-local-check.csv")
OUTPUT_MD    = os.path.join("output", "residential-local-check.md")
OUTPUT_GOOD  = os.path.join("output", "residential-local-good.txt")

TCP_TIMEOUT   = 10
TLS_TIMEOUT   = 8
PROXY_TIMEOUT = 15

# ─── 解析节点 ────────────────────────────────────────────────────────────────

def parse_node(node_str):
    """返回 dict: proto, server, port, uuid/cipher, password, params"""
    info = {"raw": node_str, "proto": "", "server": "", "port": 0,
            "uuid": "", "cipher": "", "password": "", "params": {}, "label": ""}
    try:
        if node_str.startswith("vless://"):
            m = re.search(r"vless://([^@]+)@([^:]+):(\d+)\??(.*)", node_str)
            if not m:
                return None
            uuid_str, server, port_s, query_frag = m.groups()
            query = query_frag.split("#")[0]
            params = dict(re.findall(r"([^=&#]+)=([^&#]*)", query))
            info.update({
                "proto": "vless", "server": server, "port": int(port_s),
                "uuid": uuid_str, "params": params,
                "label": uuid_str[:8],
            })
        elif node_str.startswith("ss://"):
            raw = node_str[5:].split("#")[0].strip()
            if "@" not in raw:
                return None
            user_part, host_part = raw.split("@", 1)
            user_part += "=" * (-len(user_part) % 4)
            try:
                dec = base64.b64decode(user_part).decode("utf-8", errors="ignore")
                if ":" in dec:
                    cipher, password = dec.split(":", 1)
                else:
                    cipher, password = dec, ""
            except Exception:
                cipher, password = "chacha20-ietf-poly1305", ""
            if ":" not in host_part:
                return None
            srv, port_s = host_part.rsplit(":", 1)
            info.update({
                "proto": "ss", "server": srv.strip(), "port": int(port_s),
                "cipher": cipher, "password": password,
                "label": srv.strip()[:20],
            })
        else:
            return None
    except Exception:
        return None
    return info


# ─── 测试阶段 ────────────────────────────────────────────────────────────────

def stage_tcp(info):
    """阶段1: TCP 连通性"""
    try:
        sock = socket.create_connection(
            (info["server"], info["port"]), timeout=TCP_TIMEOUT)
        sock.close()
        return True, "TCP OK"
    except Exception as e:
        return False, f"TCP FAIL: {type(e).__name__}"


def stage_tls(info):
    """阶段2: TLS 握手（仅 VLESS Reality / TLS 节点）"""
    proto = info["proto"]
    if proto != "vless":
        return True, "N/A"
    sec = info["params"].get("security", "")
    if sec not in ("reality", "tls"):
        return True, "N/A"
    sni = info["params"].get("sni", info["server"])
    try:
        sock = socket.create_connection(
            (info["server"], info["port"]), timeout=TLS_TIMEOUT)
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ss = ctx.wrap_socket(sock, server_hostname=sni, timeout=TLS_TIMEOUT)
        cipher = ss.cipher()[0] if ss.cipher() else "unknown"
        ss.close()
        return True, f"TLS OK ({cipher})"
    except Exception as e:
        return False, f"TLS FAIL: {type(e).__name__}: {str(e)[:80]}"


def stage_proxy_xray(info):
    """阶段3: 用 xray 建立 SOCKS 代理，访问 ip-api.com"""
    proto = info["proto"]
    # 先尝试 TCP 连接，不通就直接返回
    ok, msg = stage_tcp(info)
    if not ok:
        return False, "TCP", msg

    # TLS 握手检查（仅 VLESS）
    if proto == "vless":
        tls_ok, tls_msg = stage_tls(info)
        if not tls_ok:
            return False, "TLS", tls_msg

    # 生成 xray 配置
    task_id = uuid.uuid4().hex
    cfg_path = f"xray_tmp_local_{task_id}.json"

    try:
        # 解析参数
        outbound = None
        if proto == "vless":
            params = info["params"]
            outbound = {
                "protocol": "vless",
                "settings": {"vnext": [{"address": info["server"],
                                        "port": info["port"],
                                        "users": [{"id": info["uuid"],
                                                   "encryption": params.get("encryption", "none")}]}]},
                "streamSettings": {"network": params.get("type", "tcp"),
                                   "security": params.get("security", "none")},
            }
            if params.get("security") == "reality":
                outbound["streamSettings"]["realitySettings"] = {
                    "serverName": params.get("sni", info["server"]),
                    "publicKey": params.get("pbk", ""),
                    "shortId": params.get("sid", ""),
                    "fingerprint": params.get("fp", "chrome"),
                }
            elif params.get("security") == "tls":
                outbound["streamSettings"]["tlsSettings"] = {
                    "serverName": params.get("sni", info["server"]),
                    "allowInsecure": True,
                }
            if params.get("type") == "ws":
                outbound["streamSettings"]["wsSettings"] = {
                    "path": urllib.parse.unquote(params.get("path", "/")),
                    "headers": {"Host": params.get("host", info["server"])},
                }

        elif proto == "ss":
            outbound = {
                "protocol": "shadowsocks",
                "settings": {"servers": [{
                    "address": info["server"],
                    "port": info["port"],
                    "method": info["cipher"] or "chacha20-ietf-poly1305",
                    "password": info["password"],
                }]},
            }
        else:
            return False, "PROTO", f"unsupported proto: {proto}"

        config = {
            "log": {"loglevel": "none"},
            "inbounds": [{"port": 0, "listen": "127.0.0.1",
                          "protocol": "socks", "settings": {"udp": False}}],
            "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
        }

        # 找一个空闲 SOCKS 端口
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
            tmp.bind(("127.0.0.1", 0))
            socks_port = tmp.getsockname()[1]
        config["inbounds"][0]["port"] = socks_port

        with open(cfg_path, "w", encoding="utf-8") as f:
            json.dump(config, f, ensure_ascii=False)

        # 启动 xray
        proc = subprocess.Popen(
            ["./xray", "run", "-config", cfg_path],
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        )
        time.sleep(2.0)

        # 检查 xray 是否存活
        if proc.poll() is not None:
            _, stderr = proc.communicate()
            stderr_str = stderr.decode("utf-8", errors="replace").strip() if stderr else ""
            proc.close()
            return False, "XRAY", f"进程立即退出 rc={proc.returncode} stderr={stderr_str[:200]}"

        # 通过代理访问 ip-api.com
        start = time.time()
        opener = urllib.request.build_opener(urllib.request.ProxyHandler({
            "http": f"http://127.0.0.1:{socks_port}",
            "https": f"http://127.0.0.1:{socks_port}",
        }))
        try:
            req = urllib.request.Request(
                "http://ip-api.com/json/?fields=status,query,country,isp",
                headers={"User-Agent": "Mozilla/5.0"},
            )
            with opener.open(req, timeout=PROXY_TIMEOUT) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            delay = int((time.time() - start) * 1000)
            if data.get("status") == "success":
                exit_ip = data.get("query", "?")
                exit_country = data.get("country", "?")
                proc.terminate()
                proc.wait(timeout=3)
                return True, f"OK exit_ip={exit_ip} country={exit_country} delay={delay}ms"
            else:
                proc.terminate()
                proc.wait(timeout=3)
                return False, f"PROXY_FAIL status={data.get('status')}"
        except Exception as e:
            delay = int((time.time() - start) * 1000)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            return False, f"PROXY_FAIL: {type(e).__name__}: {str(e)[:100]} delay={delay}ms"

    finally:
        if os.path.exists(cfg_path):
            try:
                os.remove(cfg_path)
            except Exception:
                pass



def ensure_xray():
    """确保 xray 二进制可用，Windows 下载 .exe，Linux 下载无扩展名"""
    if sys.platform == 'win32':
        if os.path.exists('xray.exe'):
            return True
        print('[*] 正在下载 Xray-core Windows 版...')
        url = 'https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-windows-64.zip'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            with open('xray.zip', 'wb') as f:
                f.write(data)
            with zipfile.ZipFile('xray.zip', 'r') as z:
                z.extract('xray.exe')
            os.remove('xray.zip')
            print('[+] xray.exe 下载完成')
            return True
        except Exception as e:
            print(f'[!] xray 下载失败: {type(e).__name__}: {e}')
            return False
    else:
        if os.path.exists('xray'):
            return True
        print('[*] 正在下载 Xray-core Linux 版...')
        url = 'https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip'
        try:
            req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0'})
            with urllib.request.urlopen(req, timeout=60) as resp:
                data = resp.read()
            with open('xray.zip', 'wb') as f:
                f.write(data)
            with zipfile.ZipFile('xray.zip', 'r') as z:
                z.extract('xray')
            os.chmod('xray', 0o755)
            os.remove('xray.zip')
            print('[+] xray 下载完成')
            return True
        except Exception as e:
            print(f'[!] xray 下载失败: {type(e).__name__}: {e}')
            return False

def test_node(node_str, have_xray=True):
    """返回 (success, stage, detail, delay_ms, exit_ip, exit_country)"""
    info = parse_node(node_str)
    if not info:
        return False, "PARSE", "无法解析节点 URL", 0, "", ""

    # Stage 1: TCP
    tcp_ok, tcp_msg = stage_tcp(info)
    if not tcp_ok:
        return False, "TCP", tcp_msg, 0, "", ""

    # Stage 2: TLS（仅 VLESS）
    tls_ok = True
    tls_msg = "N/A"
    if info["proto"] == "vless":
        tls_ok, tls_msg = stage_tls(info)
        if not tls_ok:
            return False, "TLS", tls_msg, 0, "", ""

    # Stage 3: 代理 + 外网访问
    start = time.time()
    if not have_xray:
        ok, stage, detail = True, "TCP+TLS", "skip proxy (no xray)"
    else:
        ok, stage, detail = stage_proxy_xray(info)
    delay = int((time.time() - start) * 1000)

    # 从 detail 中提取出口信息
    exit_ip = ""
    exit_country = ""
    m = re.search(r"exit_ip=(\S+)", detail)
    if m:
        exit_ip = m.group(1)
    m = re.search(r"country=(\S+)", detail)
    if m:
        exit_country = m.group(1)

    return ok, stage, detail, delay, exit_ip, exit_country


# ─── 输出 ────────────────────────────────────────────────────────────────────

def main():
    print("=" * 60)
    print("  本地节点可用性验证 — 本机网络环境实测")
    print("=" * 60)


    # 确保 xray 可用
    have_xray = ensure_xray()
    if not have_xray:
        print("[!] xray 不可用，将跳过代理连通性测试，仅做 TCP/TLS 检测")
        print("[!] 如需完整测试，请手动下载 xray 放到脚本同目录")
        print()
    if not os.path.exists(INPUT_FILE):
        print(f"[!] 输入文件不存在: {INPUT_FILE}")
        sys.exit(1)

    with open(INPUT_FILE, encoding="utf-8") as f:
        nodes = [l.strip() for l in f if l.strip()]

    if not nodes:
        print("[!] residential-good.txt 为空，退出")
        sys.exit(0)

    print(f"[*] 读取到 {len(nodes)} 个节点，开始逐节点测试...\n")

    results = []
    total = len(nodes)

    for idx, node_str in enumerate(nodes, 1):
        info = parse_node(node_str)
        label = info["label"] if info else "???"
        server = f"{info['server']}:{info['port']}" if info else "?"
        proto  = info["proto"] if info else "?"

        print(f"[{idx}/{total}] {label}  ({proto} {server})")

        ok, stage, detail, delay, exit_ip, exit_country = test_node(node_str, have_xray)

        if ok:
            grade = "OK"
            flag  = "OK"
        elif stage == "TCP":
            grade = "TCP 不通"
            flag  = "TCP fail"
        elif stage == "TLS":
            grade = "TLS 握手失败"
            flag  = "TLS fail"
        elif stage == "XRAY":
            grade = "Xray 启动失败"
            flag  = "Xray fail"
        elif stage == "PROTO":
            grade = "不支持的协议"
            flag  = "proto??"
        else:
            grade = "代理测试失败"
            flag  = "proxy fail"

        print(f"      [{flag}] {detail}")
        if delay:
            print(f"      延迟={delay}ms  出口IP={exit_ip or 'N/A'}  国家={exit_country or 'N/A'}")
        print()

        results.append({
            "index":        idx,
            "label":        label,
            "proto":        proto,
            "server":       server,
            "node_url":     node_str,
            "connect_ok":   "OK" if ok else "FAIL",
            "fail_stage":   stage,
            "fail_detail":  detail,
            "delay_ms":     delay,
            "exit_ip":      exit_ip,
            "exit_country": exit_country,
        })

    # ── 输出结果文件 ──
    os.makedirs("output", exist_ok=True)

    # CSV
    csv_rows = [
        ["序号", "名称", "协议", "服务器地址", "连接状态", "失败阶段", "详情",
         "延迟(ms)", "出口IP", "出口国家", "原始URL"],
    ]
    for r in results:
        csv_rows.append([
            r["index"], r["label"], r["proto"], r["server"],
            r["connect_ok"], r["fail_stage"], r["fail_detail"][:60],
            r["delay_ms"], r["exit_ip"] or "(未获取)", r["exit_country"] or "(未获取)",
            r["node_url"],
        ])
    try:
        import openpyxl
        wb = openpyxl.Workbook()
        ws = wb.active
        ws.title = "Local Check"
        for row in csv_rows:
            ws.append(row)
        for cell in ws[1]:
            cell.font = openpyxl.styles.Font(bold=True)
        wb.save(OUTPUT_CSV)
        print(f"\n[+] CSV 已保存: {OUTPUT_CSV}")
    except ImportError:
        with open(OUTPUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
            import csv
            w = csv.writer(f)
            w.writerows(csv_rows)
        print(f"\n[+] CSV 已保存 (无 openpyxl): {OUTPUT_CSV}")

    # Markdown
    ok_n  = sum(1 for r in results if r["connect_ok"] == "OK")
    fail_n = total - ok_n
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    md_lines = [
        "# 本地节点可用性验证报告",
        "",
        f"> 生成时间：{now_str}  |  输入节点数：{total}  |  本机可用：{ok_n}  |  不可用：{fail_n}",
        "",
        "## 详细结果",
        "",
        "| # | 名称 | 协议 | 服务器 | 状态 | 失败阶段 | 详情 | 延迟 | 出口IP | 国家 |",
        "|---|:---|:---|:---|:---|:---|:---|---:|:---|:---|",
    ]
    for r in results:
        md_lines.append(
            f"| {r['index']} | {r['label'][:20]} | {r['proto']} | {r['server'][:25]} "
            f"| {r['connect_ok']} | {r['fail_stage']} | {r['fail_detail'][:40]} "
            f"| {r['delay_ms']}ms | {r['exit_ip'] or 'N/A'} | {r['exit_country'] or 'N/A'} |"
        )

    md_lines += ["", "## 说明", "",
        "- **OK**：本机 TCP + TLS + Xray 代理 + 外网访问全部通过",
        "- **TCP**：TCP 端口无法连接（服务器被封/关闭）",
        "- **TLS**：TCP 通但 TLS 握手失败（Reality/TLS 参数错误）",
        "- **XRAY**：xray 进程启动后立即退出（配置错误或内核问题）",
        "- **PROXY**：代理建立成功但 ip-api.com 访问失败（节点限速/无流量）",
    ]

    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md_lines))
    print(f"[+] Markdown 报告已保存: {OUTPUT_MD}")

    # residential-local-good.txt（仅 OK 节点）
    good_nodes = [r["node_url"] for r in results if r["connect_ok"] == "OK"]
    with open(OUTPUT_GOOD, "w", encoding="utf-8") as f:
        for node in good_nodes:
            f.write(node.strip() + "\n")
    print(f"\n\U0001f3e0 本机可用节点：{len(good_nodes)} 个")
    for idx, node in enumerate(good_nodes, 1):
        info = parse_node(node)
        ip   = next((r["exit_ip"] for r in results if r["node_url"] == node), "N/A")
        ct   = next((r["exit_country"] for r in results if r["node_url"] == node), "N/A")
        print(f"  {idx}. {ct} {ip}")
    print(f"\n\U0001f4c4 已生成：{OUTPUT_GOOD}")
    if len(good_nodes) == 0:
        print("\u672c\u673a\u7f51\u7edc\u73af\u5883\u4e0b\u6ca1\u6709\u53ef\u7528\u8282\u70b9\uff0c\u8bf7\u8054\u7cfb\u8282\u70b9\u63d0\u4f9b\u5546\u786e\u8ba4\u670d\u52a1\u5668\u72b6\u6001\u3002")
    print("=" * 60)


if __name__ == "__main__":
    main()

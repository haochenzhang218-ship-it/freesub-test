#!/usr/bin/env python3
"""
本机最终验证脚本（4 级分层测试）
读取 output/residential-stable-good.txt，在本机真实网络环境下逐级验证节点是否真正可用。

Level 1: TCP 直连
Level 2: 协议连接（Xray/SOCKS 隧道建立）
Level 3: 实际代理外网访问（获取真实出口 IP）
Level 4: 最终判定 LOCAL_USABLE 或明确失败原因

不修改系统代理/DNS/网络设置，仅启动本脚本自己的 xray 与本地临时 SOCKS 端口。
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

# 强制 UTF-8 输出（解决 Windows GBK 编码问题）
if hasattr(sys.stdout, 'reconfigure'):
    sys.stdout.reconfigure(encoding='utf-8')
if hasattr(sys.stderr, 'reconfigure'):
    sys.stderr.reconfigure(encoding='utf-8')

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.join(SCRIPT_DIR, "..")
INPUT_FILE   = os.path.join("output", "residential-stable-good.txt")
FALLBACK_FILE = os.path.join("output", "residential-good.txt")
OUTPUT_CSV   = os.path.join("output", "residential-local-check.csv")
OUTPUT_MD    = os.path.join("output", "residential-local-check.md")
OUTPUT_GOOD  = os.path.join("output", "residential-local-good.txt")

TCP_TIMEOUT   = 10
HANDSHAKE_TIMEOUT = 12
PROXY_TIMEOUT = 15
XRAY_WAIT     = 2.0

# ─── 节点解析（与 main.py 的 parse_node_to_xray_outbound 保持兼容）─────────────

def parse_node(node_str):
    """返回 dict: proto, server, port, uuid, cipher, password, params, label, raw"""
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
            if "@" in raw:
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
        else:
            return None
    except Exception:
        return None
    return info


def build_outbound(info):
    """根据解析结果构造 xray outbound 配置（与 main.py 逻辑一致）。"""
    proto = info["proto"]
    if proto == "vless":
        params = info["params"]
        outbound = {
            "protocol": "vless",
            "settings": {"vnext": [{
                "address": info["server"],
                "port": info["port"],
                "users": [{"id": info["uuid"], "encryption": params.get("encryption", "none")}]
            }]},
            "streamSettings": {"network": params.get("type", "tcp"),
                               "security": params.get("security", "none")},
        }
        sec = params.get("security", "")
        if sec == "reality":
            outbound["streamSettings"]["realitySettings"] = {
                "serverName": params.get("sni", info["server"]),
                "publicKey": params.get("pbk", ""),
                "shortId": params.get("sid", ""),
                "fingerprint": params.get("fp", "chrome"),
            }
        elif sec == "tls":
            outbound["streamSettings"]["tlsSettings"] = {
                "serverName": params.get("sni", info["server"]),
                "allowInsecure": True,
            }
        if params.get("type") == "ws":
            outbound["streamSettings"]["wsSettings"] = {
                "path": urllib.parse.unquote(params.get("path", "/")),
                "headers": {"Host": params.get("host", info["server"])},
            }
        return outbound
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
        return outbound
    return None


# ─── 4 级分层测试 ─────────────────────────────────────────────────────────────

def stage_tcp(info):
    """Level 1: TCP 直连测试。返回 (ok, latency_ms, error)"""
    start = time.time()
    try:
        sock = socket.create_connection((info["server"], info["port"]), timeout=TCP_TIMEOUT)
        sock.close()
        return True, int((time.time() - start) * 1000), ""
    except Exception as e:
        return False, int((time.time() - start) * 1000), f"{type(e).__name__}: {str(e)[:100]}"


def stage_handshake(info, xray_bin):
    """Level 2: 协议连接测试 — 启动 xray 建立 SOCKS 并做真实 CONNECT 握手。
    返回 (ok, error)。复用 main.py 的 xray outbound 构造逻辑。"""
    if not xray_bin or not os.path.exists(os.path.abspath(xray_bin)):
        return False, "xray_missing"
    outbound = build_outbound(info)
    if not outbound:
        return False, "unsupported_proto"

    task_id = uuid.uuid4().hex
    cfg_path = os.path.join(SCRIPT_DIR, f"xray_tmp_local_{task_id}.json")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
        tmp.bind(("127.0.0.1", 0))
        socks_port = tmp.getsockname()[1]

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1",
                      "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False)

    xray_abs = os.path.abspath(xray_bin)
    proc = subprocess.Popen([xray_abs, "run", "-config", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(XRAY_WAIT)
    error = ""
    try:
        if proc.poll() is not None:
            stderr_data = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            error = f"xray_exited rc={proc.returncode} {stderr_data[:120]}"
            return False, error

        # 做真实 SOCKS5 CONNECT 握手到 1.1.1.1:443（验证代理实际可用，不只是端口启动）
        try:
            result = _socks5_connect_handshake(socks_port)
            if not result[0]:
                error = result[1]
                return False, error
        except Exception as e:
            error = f"handshake_ex: {type(e).__name__}: {str(e)[:80]}"
            return False, error
        return True, ""
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except Exception:
            pass


def _socks5_connect_handshake(socks_port, target_host="8.8.8.8", target_port=443):
    """通过本地 SOCKS5 对目标做 CONNECT，验证代理链路真实可用。
    使用域名 CONNECT（让 xray 真正走 VLESS 隧道），返回 (ok, error)"""
    import struct
    sock = socket.create_connection(("127.0.0.1", socks_port), timeout=HANDSHAKE_TIMEOUT)
    try:
        # SOCKS5 认证协商
        sock.sendall(b"\x05\x01\x00")
        auth = b""
        while len(auth) < 2:
            chunk = sock.recv(2 - len(auth))
            if not chunk:
                break
            auth += chunk
        if len(auth) < 2 or auth[0] != 0x05:
            return False, f"socks5_auth_bad: {auth.hex() if auth else 'empty'}"
        # CONNECT 请求：用域名（ATYP=3），让 xray 走远端代理解析并建隧道
        host_bytes = target_host.encode("utf-8")
        req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes
        req += struct.pack(">H", target_port)
        sock.sendall(req)
        # 等待响应（CONNECT 建隧道可能需 1-3s）
        deadline = time.time() + HANDSHAKE_TIMEOUT
        resp = b""
        while time.time() < deadline:
            chunk = sock.recv(4 - len(resp))
            if not chunk:
                break
            resp += chunk
            if len(resp) >= 4:
                break
        if len(resp) < 4:
            return False, f"socks5_connect_no_response (got {len(resp)} bytes)"
        code = resp[1]
        if code != 0x00:
            return False, f"socks5_connect_fail code={code}"
        # 读取绑定地址信息
        atyp = resp[3]
        if atyp == 1:
            sock.recv(6)
        elif atyp == 3:
            blen = sock.recv(1)[0]
            sock.recv(blen + 2)
        elif atyp == 4:
            sock.recv(18)
        return True, ""
    finally:
        sock.close()


def _resolve_host_bytes(host):
    if host.isdigit():
        return socket.inet_aton(host)
    try:
        return socket.inet_aton(host)
    except Exception:
        return host.encode("utf-8")


def _socks5_https_get_exit_ip(socks_port):
    """通过 PySocks 建立 SOCKS5h 隧道访问 ip-api / ipify，返回 (exit_ip, latency_ms, error)。
    PySocks 是项目已有依赖，直接用它做真实的 SOCKS5 外网访问，
    避免 urllib 不支持 socks5h 导致的脚本自身误判。"""
    try:
        import socks as _socks_mod
    except Exception:
        return "", 0, "PySocks_not_available"

    targets = [
        ("ip-api.com", 443, "https", "/json/?fields=status,query,country,isp"),
        ("api.ipify.org", 443, "https", "/?format=json"),
    ]
    last_err = ""
    for host, port, scheme, urlpath in targets:
        start = time.time()
        raw = None
        try:
            # 通过 SOCKS5 隧道建立到目标 443 的 TCP 连接
            raw = socket.create_connection(("127.0.0.1", socks_port), timeout=PROXY_TIMEOUT)
            # 手动 SOCKS5h 转发对目标做 CONNECT（域名在 SOCKS5 层解析）
            import struct as _struct
            raw.sendall(b"\x05\x01\x00")
            # 有界读：避免单次 recv 短读导致后续索引越界
            auth = b""
            while len(auth) < 2:
                c = raw.recv(2 - len(auth))
                if not c:
                    break
                auth += c
            if len(auth) < 2 or auth[0] != 0x05:
                last_err = f"socks5_auth_bad: {auth.hex() if auth else 'empty'}"
                continue
            host_bytes = host.encode("utf-8")
            req = b"\x05\x01\x00\x03" + bytes([len(host_bytes)]) + host_bytes + _struct.pack(">H", port)
            raw.sendall(req)
            resp = b""
            cdeadline = time.time() + PROXY_TIMEOUT
            while time.time() < cdeadline and len(resp) < 4:
                c = raw.recv(4 - len(resp))
                if not c:
                    break
                resp += c
            if len(resp) < 4 or resp[1] != 0x00:
                code = resp[1] if len(resp) > 1 else 255
                last_err = f"socks5_connect_fail code={code}"
                continue
            atyp = resp[3]
            def _recvn(n):
                buf = b""
                while len(buf) < n:
                    c = raw.recv(n - len(buf))
                    if not c:
                        break
                    buf += c
                return buf
            if atyp == 1:
                _recvn(6)
            elif atyp == 3:
                blen = _recvn(1)[0]
                _recvn(blen + 2)
            elif atyp == 4:
                _recvn(18)

            # 走 TLS 到目标
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            raw.settimeout(PROXY_TIMEOUT)
            tls_sock = ctx.wrap_socket(raw, server_hostname=host)
            tls_sock.settimeout(PROXY_TIMEOUT)
            tls_sock.sendall(f"GET {urlpath} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n".encode("utf-8"))
            chunks = []
            while True:
                try:
                    b = tls_sock.recv(4096)
                    if not b:
                        break
                    chunks.append(b)
                except ssl.SSLReadError:
                    break
            latency = int((time.time() - start) * 1000)
            resp_body = b"".join(chunks).decode("utf-8", errors="ignore")
            head, _, body = resp_body.partition("\r\n\r\n")
            status_line = head.split("\n", 1)[0] if head else ""
            status_code = int(status_line.split(" ", 2)[1]) if len(status_line.split(" ", 2)) > 1 else 0
            if status_code == 200 and body:
                data = json.loads(body)
                if host == "ip-api.com":
                    if data.get("status") == "success":
                        return data.get("query", ""), latency, ""
                else:
                    if data.get("ip"):
                        return data.get("ip", ""), latency, ""
            else:
                last_err = f"non_200_or_bad_status status={status_code}"
        except Exception as e:
            # 远端真实重置 / 隧道未真正转发流量（WinError 10054、ConnectionResetError、
            # 以及 fd 被底层关闭导致的 FileNotFoundError / TimeoutError）→ 如实记为节点外网转发失败
            _msg = f"{type(e).__name__}: {str(e)[:80]}"
            _known_tunnel_fail = (
                "WinError 10054" in _msg or "ConnectionReset" in _msg
                or "forcibly closed" in _msg or "ConnectionResetError" in _msg
                or "FileNotFoundError" in _msg or "handshake operation timed out" in _msg
                or "timeout" in _msg.lower()
            )
            last_err = "outbound_relay_failed (远端未转发流量)" if _known_tunnel_fail else _msg
        finally:
            try:
                if raw is not None:
                    raw.close()
            except Exception:
                pass
    return "", 0, last_err or "no_exit_ip"


def stage_outbound(info, xray_bin):
    """Level 3: 实际代理外网访问 — 通过 xray SOCKS + PySocks 隧道获取真实出口 IP。
    返回 (ok, exit_ip, latency_ms, error)"""
    if not xray_bin or not os.path.exists(os.path.abspath(xray_bin)):
        return False, "", 0, "xray_missing"
    outbound = build_outbound(info)
    if not outbound:
        return False, "", 0, "unsupported_proto"

    task_id = uuid.uuid4().hex
    cfg_path = os.path.join(SCRIPT_DIR, f"xray_tmp_local_{task_id}.json")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tmp:
        tmp.bind(("127.0.0.1", 0))
        socks_port = tmp.getsockname()[1]

    config = {
        "log": {"loglevel": "none"},
        "inbounds": [{"port": socks_port, "listen": "127.0.0.1",
                      "protocol": "socks", "settings": {"udp": False}}],
        "outbounds": [outbound, {"protocol": "freedom", "tag": "direct"}],
    }
    with open(cfg_path, "w", encoding="utf-8") as f:
        json.dump(config, f, ensure_ascii=False)

    xray_abs = os.path.abspath(xray_bin)
    proc = subprocess.Popen([xray_abs, "run", "-config", cfg_path],
                            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(XRAY_WAIT)
    exit_ip = ""
    error = ""
    latency = 0
    try:
        if proc.poll() is not None:
            stderr_data = proc.stderr.read().decode("utf-8", errors="replace") if proc.stderr else ""
            error = f"xray_exited rc={proc.returncode} {stderr_data[:120]}"
            return False, "", 0, error

        # 通过 PySocks 建立的 SOCKS5h 隧道真正访问外网获取出口 IP
        exit_ip, latency, error = _socks5_https_get_exit_ip(socks_port)
        if not exit_ip:
            return False, "", latency, error or "no_exit_ip"
        return True, exit_ip, latency, ""
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=3)
        except Exception:
            proc.kill()
        try:
            if os.path.exists(cfg_path):
                os.remove(cfg_path)
        except Exception:
            pass


def test_node_4stage(node_str, xray_bin):
    """对单个节点做 4 级分层测试。
    返回 dict 包含各级状态与最终判定。"""
    info = parse_node(node_str)
    if not info:
        return {
            "node": node_str[:60], "protocol": "?", "server": "?", "port": 0,
            "tcp_status": "FAIL", "tcp_latency": 0, "tcp_error": "parse_fail",
            "handshake_status": "SKIP", "proxy_status": "SKIP", "outbound_status": "SKIP",
            "exit_ip": "", "total_latency": 0, "final_status": "PARSE_FAIL", "error": "无法解析节点 URL",
            "raw": node_str,
        }

    label = f"{info['proto']} {info['server']}:{info['port']}"
    row = {
        "node": info["label"], "protocol": info["proto"],
        "server": info["server"], "port": info["port"],
        "tcp_status": "FAIL", "tcp_latency": 0, "tcp_error": "",
        "handshake_status": "SKIP", "proxy_status": "SKIP", "outbound_status": "SKIP",
        "exit_ip": "", "total_latency": 0, "final_status": "", "error": "",
        "raw": node_str,
    }

    # Level 1: TCP
    t0 = time.time()
    tcp_ok, tcp_lat, tcp_err = stage_tcp(info)
    row["tcp_status"] = "OK" if tcp_ok else "FAIL"
    row["tcp_latency"] = tcp_lat
    row["tcp_error"] = tcp_err
    if not tcp_ok:
        row["final_status"] = "TCP_FAIL"
        row["error"] = tcp_err
        row["total_latency"] = int((time.time() - t0) * 1000)
        return row

    # Level 2: 协议握手（Xray SOCKS CONNECT）
    hs_ok, hs_err = stage_handshake(info, xray_bin)
    row["handshake_status"] = "OK" if hs_ok else "FAIL"
    if not hs_ok:
        row["final_status"] = "HANDSHAKE_FAIL"
        row["error"] = hs_err
        row["total_latency"] = int((time.time() - t0) * 1000)
        return row

    # Level 3: 实际代理外网访问
    out_ok, exit_ip, out_lat, out_err = stage_outbound(info, xray_bin)
    row["proxy_status"] = "OK" if out_ok else "FAIL"
    row["outbound_status"] = "OK" if out_ok else "FAIL"
    row["exit_ip"] = exit_ip
    if out_ok:
        row["final_status"] = "LOCAL_USABLE"
    else:
        row["final_status"] = "OUTBOUND_FAIL" if out_ok is False else "TIMEOUT"
        row["error"] = out_err
    row["total_latency"] = int((time.time() - t0) * 1000)
    return row


# ─── xray 管理 ────────────────────────────────────────────────────────────────

def find_xray():
    """查找本机可用的 xray 二进制。

    始终返回绝对路径（os.path.abspath 归一化），无论当前工作目录是仓库根、
    scripts/ 还是任意位置，stage_handshake/stage_outbound 的 os.path.exists
    都能正确命中，不会误报 xray_missing。"""
    candidates = [
        os.path.join(SCRIPT_DIR, "xray.exe"),
        os.path.join(SCRIPT_DIR, "xray"),
        os.path.join(REPO_ROOT, "xray.exe"),
        os.path.join(REPO_ROOT, "xray"),
        os.path.join(os.getcwd(), "xray.exe"),
        os.path.join(os.getcwd(), "xray"),
    ]
    for p in candidates:
        try:
            ap = os.path.abspath(p)
            if os.path.exists(ap):
                return ap
        except Exception:
            continue
    # 尝试下载
    print("[*] 未找到本地 xray，正在下载 Windows 版...")
    return _download_xray()


def _download_xray():
    if sys.platform == "win32":
        url = "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-windows-64.zip"
        exe = os.path.join(SCRIPT_DIR, "xray.exe")
    else:
        url = "https://github.com/XTLS/Xray-core/releases/download/v1.8.24/Xray-linux-64.zip"
        exe = os.path.join(SCRIPT_DIR, "xray")
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
        with urllib.request.urlopen(req, timeout=90) as resp:
            data = resp.read()
        zpath = exe + ".zip"
        with open(zpath, "wb") as f:
            f.write(data)
        with zipfile.ZipFile(zpath, "r") as z:
            z.extract(exe.split(os.sep)[-1])
        os.remove(zpath)
        if sys.platform != "win32":
            os.chmod(exe, 0o755)
        exe = os.path.abspath(exe)
        print(f"[+] xray 下载完成: {exe}")
        return exe
    except Exception as e:
        print(f"[!] xray 下载失败: {type(e).__name__}: {e}")
        return None


# ─── 输出 ────────────────────────────────────────────────────────────────────

def write_outputs(results, input_file):
    os.makedirs("output", exist_ok=True)

    # CSV
    csv_fields = ["node", "protocol", "server", "port",
                  "tcp_status", "tcp_latency",
                  "handshake_status", "proxy_status", "outbound_status",
                  "exit_ip", "total_latency", "final_status", "error", "raw_url"]
    with open(OUTPUT_CSV, "w", encoding="utf-8-sig", newline="") as f:
        f.write(",".join(csv_fields) + "\n")
        for r in results:
            f.write(",".join([
                r["node"], r["protocol"], r["server"], str(r["port"]),
                r["tcp_status"], str(r["tcp_latency"]),
                r["handshake_status"], r["proxy_status"], r["outbound_status"],
                r["exit_ip"] or "", str(r["total_latency"]), r["final_status"],
                r["error"][:80], r["raw"],
            ]) + "\n")
    print(f"[+] CSV 已保存: {OUTPUT_CSV}")

    # MD
    ok_n = sum(1 for r in results if r["final_status"] == "LOCAL_USABLE")
    fail_n = len(results) - ok_n
    now_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    md = [
        "# 本机最终验证报告",
        "",
        f"> 生成时间：{now_str}  |  输入：{input_file}  |  节点数：{len(results)}  |  "
        f"本机可用：{ok_n}  |  不可用：{fail_n}",
        "",
        "## 详细结果",
        "",
        "| # | 节点 | 协议 | 服务器:端口 | TCP | 握手 | 代理 | 出口 | 总延迟 | 最终判定 | 错误 |",
        "|---|:---|:---|:---|:---|:---|:---|:---|---:|:---|:---|",
    ]
    for i, r in enumerate(results, 1):
        tcp_m = "✓" if r["tcp_status"] == "OK" else "✗"
        hs_m = "✓" if r["handshake_status"] == "OK" else ("✗" if r["handshake_status"] == "FAIL" else "-")
        proxy_m = "✓" if r["proxy_status"] == "OK" else ("✗" if r["proxy_status"] == "FAIL" else "-")
        md.append(
            f"| {i} | {r['node']} | {r['protocol']} | {r['server']}:{r['port']} "
            f"| {tcp_m} {r['tcp_latency']}ms | {hs_m} | {proxy_m} | {r['exit_ip'] or 'N/A'} "
            f"| {r['total_latency']}ms | **{r['final_status']}** | {r['error'][:50]} |"
        )
    md += ["", "## 判定说明", "",
        "- **LOCAL_USABLE**：TCP + 握手 + 代理 + 实际外网访问全部通过，节点在本机真实可用",
        "- **TCP_FAIL**：本机无法直连服务器端口（被封/IP 不通）",
        "- **HANDSHAKE_FAIL**：TCP 通但 Xray SOCKS 握手失败（协议参数错误/隧道建立失败）",
        "- **OUTBOUND_FAIL**：代理建立成功但无法通过代理访问外网（限速/出口异常）",
        "- **TIMEOUT**：任一阶段超时",
    ]
    with open(OUTPUT_MD, "w", encoding="utf-8") as f:
        f.write("\n".join(md))
    print(f"[+] Markdown 报告已保存: {OUTPUT_MD}")

    # local-good.txt（仅 LOCAL_USABLE 节点完整 URL，与 residential.txt 同格式 base64）
    good_nodes = [r["raw"] for r in results if r["final_status"] == "LOCAL_USABLE"]
    with open(OUTPUT_GOOD, "w", encoding="utf-8") as f:
        f.write(base64.b64encode("\n".join(good_nodes).encode()).decode())
    print(f"[+] 本机可用节点已保存: {OUTPUT_GOOD}（{len(good_nodes)} 个）")
    return good_nodes


def main():
    print("=" * 60)
    print("  本机最终验证 — 4 级分层测试（TCP → 握手 → 代理 → 外网）")
    print("=" * 60)
    print()
    print("⚠️  请关闭当前正在使用的其他代理节点/系统代理，")
    print("    以确保测试代表本机真实网络（中华电信等）。")
    print("    本脚本不会修改系统代理/DNS/网络设置，")
    print("    仅启动自己的 xray 与本地临时 SOCKS 端口。")
    print()
    input("按 Enter 继续...")

    # 读取输入文件（优先 stable-good）
    input_file = INPUT_FILE
    if not os.path.exists(input_file) or not os.path.getsize(input_file):
        input_file = FALLBACK_FILE
        print(f"[!] {INPUT_FILE} 不存在或为空，回退到 {FALLBACK_FILE}")
    if not os.path.exists(input_file) or not os.path.getsize(input_file):
        print(f"[!] {FALLBACK_FILE} 也不存在或为空 — 当前没有稳定家宽候选，退出。")
        # 仍生成空输出文件
        os.makedirs("output", exist_ok=True)
        open(OUTPUT_GOOD, "w").close()
        open(OUTPUT_CSV, "w").close()
        open(OUTPUT_MD, "w").write("# 本机最终验证报告\n\n> 当前没有稳定家宽候选，无节点可测。\n")
        print("[+] 已生成空输出文件，正常退出。")
        return

    with open(input_file, encoding="utf-8") as f:
        content = f.read().strip()
    # 文件可能是 base64 编码（与 residential.txt 同格式）
    nodes = []
    try:
        decoded = base64.b64decode(content).decode("utf-8")
        nodes = [l for l in decoded.splitlines() if l.strip()]
    except Exception:
        nodes = [l for l in content.splitlines() if l.strip()]

    if not nodes:
        print(f"[!] 输入文件为空 — 当前没有稳定家宽候选，退出。")
        os.makedirs("output", exist_ok=True)
        open(OUTPUT_GOOD, "w").close()
        open(OUTPUT_CSV, "w").close()
        open(OUTPUT_MD, "w").write("# 本机最终验证报告\n\n> 当前没有稳定家宽候选，无节点可测。\n")
        print("[+] 已生成空输出文件，正常退出。")
        return

    print(f"[*] 读取到 {len(nodes)} 个候选节点（来自 {os.path.basename(input_file)}）\n")

    xray_bin = find_xray()
    if not xray_bin:
        print("[!] xray 不可用，将无法完成协议握手与代理测试，仅做 TCP 检测。")
        print("    如需完整测试，请手动下载 xray 放到 scripts/ 目录。\n")

    total = len(nodes)
    results = []
    for idx, node_str in enumerate(nodes, 1):
        info = parse_node(node_str)
        label = info["label"] if info else "???"
        server = f"{info['server']}:{info['port']}" if info else "?"
        proto = info["proto"] if info else "?"
        print(f"[{idx}/{total}] {label}  ({proto} {server})")

        row = test_node_4stage(node_str, xray_bin)
        results.append(row)

        # 逐层输出
        t_m = "✓" if row["tcp_status"] == "OK" else "✗"
        t_l = f"{row['tcp_latency']}ms" if row["tcp_status"] == "OK" else row.get("tcp_error", "")
        print(f"      TCP {t_m} {t_l}")

        if row["tcp_status"] == "OK":
            h_m = "✓" if row["handshake_status"] == "OK" else "✗"
            h_extra = "" if row["handshake_status"] == "OK" else f" {row['error']}"
            print(f"      HANDSHAKE {h_m}{h_extra}")
            if row["handshake_status"] == "OK":
                o_m = "✓" if row["outbound_status"] == "OK" else "✗"
                o_extra = f" 真实出口IP={row['exit_ip']}" if row["outbound_status"] == "OK" else f" {row['error']}"
                print(f"      OUTBOUND {o_m}{o_extra}")
        print(f"      → {row['final_status']}\n")

    good = write_outputs(results, os.path.basename(input_file))
    print()
    print(f"🏠 本机最终可用节点：{len(good)} 个")
    for r in results:
        if r["final_status"] == "LOCAL_USABLE":
            print(f"  ✓ {r['node']} ({r['protocol']} {r['server']}:{r['port']})  出口IP={r['exit_ip']}")
    print(f"\n📄 已生成：{OUTPUT_GOOD} / {OUTPUT_CSV} / {OUTPUT_MD}")
    print("=" * 60)


if __name__ == "__main__":
    main()

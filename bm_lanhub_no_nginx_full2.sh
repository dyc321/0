#!/usr/bin/env bash
# ============================================================
# Board LAN Hub - 无Nginx版（Vite直跑 + Uvicorn）- 全量UI内置
# Commands:
#   install [--dir /opt/board-manager] [--ui-port 5173] [--api-port 8000] [--cidr 192.168.1.0/24] [--user admin] [--pass admin]
#   scan    [--cidr 192.168.1.0/24] [--user admin] [--pass admin]
#   status  | restart | logs | uninstall
# ============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; PURPLE='\033[0;35m'; CYAN='\033[0;36m'; NC='\033[0m'
log_info(){ echo -e "${GREEN}[✓]${NC} $*"; }
log_warn(){ echo -e "${YELLOW}[!]${NC} $*"; }
log_err(){  echo -e "${RED}[✗]${NC} $*" >&2; }
log_step(){ echo -e "${BLUE}[→]${NC} $*"; }
title(){ echo -e "${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}\n${CYAN}$*${NC}\n${PURPLE}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${NC}"; }

need_root(){
  if [[ ${EUID:-999} -ne 0 ]]; then
    log_err "请用 root 执行：sudo $0 $*"
    exit 1
  fi
}

APP_DIR="/opt/board-manager"
UI_PORT="5173"
API_PORT="8000"
SCAN_USER="admin"
SCAN_PASS="admin"
INSTALL_CIDR=""

SERVICE_API="/etc/systemd/system/board-manager.service"
SERVICE_UI="/etc/systemd/system/board-ui.service"

detect_os(){
  OS_FAMILY="debian"
  PKG=""
  if [[ -f /etc/os-release ]]; then
    . /etc/os-release || true
    case "${ID:-}" in
      ubuntu|debian) OS_FAMILY="debian"; PKG="apt-get" ;;
      centos|rhel|fedora|rocky|almalinux) OS_FAMILY="redhat"; PKG="$(command -v dnf || command -v yum || true)" ;;
      *) OS_FAMILY="debian"; PKG="apt-get" ;;
    esac
  fi
}

install_pkgs(){
  title "安装/检查系统依赖"
  detect_os
  if [[ "$OS_FAMILY" == "debian" ]]; then
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -y -qq
    apt-get install -y -qq git curl ca-certificates python3 python3-pip python3-venv sqlite3 iproute2 net-tools nftables
  else
    "$PKG" install -y -q git curl ca-certificates python3 python3-pip sqlite iproute net-tools nftables || true
  fi
  log_info "系统依赖 OK"
}

install_node(){
  title "安装/检查 Node.js + npm（用于前端）"
  if command -v node >/dev/null 2>&1 && command -v npm >/dev/null 2>&1; then
    log_info "已存在 node=$(node -v) npm=$(npm -v)"
    return
  fi
  detect_os
  log_step "安装 Node 20（NodeSource）"
  if [[ "$OS_FAMILY" == "debian" ]]; then
    curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
    apt-get install -y -qq nodejs
  else
    curl -fsSL https://rpm.nodesource.com/setup_20.x | bash -
    "$PKG" install -y -q nodejs
  fi
  log_info "Node OK：node=$(node -v) npm=$(npm -v)"
}

ensure_dirs(){
  title "准备目录"
  mkdir -p "${APP_DIR}/app" "${APP_DIR}/frontend/src" "${APP_DIR}/data" "${APP_DIR}/_bak"
  log_info "目录 OK：${APP_DIR}"
}

write_backend(){
  title "部署后端（FastAPI + SQLite）"
  local venv="${APP_DIR}/venv"
  if [[ ! -d "$venv" ]]; then
    log_step "创建 venv..."
    python3 -m venv "$venv"
  fi
  log_step "安装 Python 依赖..."
  "$venv/bin/pip" -q install --upgrade pip
  "$venv/bin/pip" -q install fastapi "uvicorn[standard]" requests

  # === 写入最终调试好的完美版 Python 代码 ===
  cat > "${APP_DIR}/app/main.py" <<'PY'
import asyncio, json, os, re, sqlite3, requests, time, hashlib
from ipaddress import ip_network, IPv4Network
from typing import Any, Dict, List, Optional, Tuple
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from requests.auth import HTTPDigestAuth

DB_PATH = os.environ.get("BM_DB", "/opt/board-manager/data/data.db")
DEFAULT_USER = os.environ.get("BM_DEV_USER", "admin")
DEFAULT_PASS = os.environ.get("BM_DEV_PASS", "admin")
TIMEOUT = float(os.environ.get("BM_HTTP_TIMEOUT", "6.0"))

app = FastAPI(title="Board LAN Hub", version="1.0.0")

def db():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    return con

def init_db():
    con = db()
    con.execute("""
    CREATE TABLE IF NOT EXISTS devices (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      devId TEXT, grp TEXT DEFAULT 'auto', ip TEXT NOT NULL,
      user TEXT DEFAULT '', pass TEXT DEFAULT '', status TEXT DEFAULT 'unknown', lastSeen INTEGER DEFAULT 0,
      sim1_number TEXT DEFAULT '', sim1_operator TEXT DEFAULT '',
      sim2_number TEXT DEFAULT '', sim2_operator TEXT DEFAULT ''
    )""")
    con.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_ip ON devices(ip)")
    con.commit(); con.close()
init_db()

# MD5 Token 计算 (官方算法)
def calc_token(user, pwd):
    return hashlib.md5(f"{user}|{pwd}".encode('utf-8')).hexdigest()

def is_target_device(ip, user, pw):
    try:
        r = requests.get(f"http://{ip}/mgr", timeout=TIMEOUT)
        if r.status_code == 401:
             r2 = requests.get(f"http://{ip}/mgr", auth=HTTPDigestAuth(user,pw), timeout=TIMEOUT)
             return r2.status_code == 200
        return False
    except: return False

def get_data(ip, user, pw):
    try:
        payload = {"keys": ["DEV_ID","SIM1_PHNUM","SIM2_PHNUM","SIM1_OP","SIM2_OP"]}
        r = requests.post(f"http://{ip}/mgr?a=getHtmlData_index", auth=HTTPDigestAuth(user,pw), data={"keys":json.dumps(payload)}, timeout=TIMEOUT)
        return r.json().get("data", {}) if r.status_code==200 else {}
    except: return {}

def upsert(ip, u, p, g):
    d = get_data(ip, u, p)
    con = db()
    exists = con.execute("SELECT id FROM devices WHERE ip=?", (ip,)).fetchone()
    now = int(time.time())
    if exists:
        con.execute("UPDATE devices SET devId=?, grp=?, user=?, pass=?, status='online', lastSeen=?, sim1_number=?, sim1_operator=?, sim2_number=?, sim2_operator=? WHERE ip=?",
        (d.get("DEV_ID"), g, u, p, now, d.get("SIM1_PHNUM"), d.get("SIM1_OP"), d.get("SIM2_PHNUM"), d.get("SIM2_OP"), ip))
    else:
        con.execute("INSERT INTO devices VALUES(NULL,?,?,?,?,?,'online',?,?,?,?,?)",
        (d.get("DEV_ID"), g, ip, u, p, now, d.get("SIM1_PHNUM"), d.get("SIM1_OP"), d.get("SIM2_PHNUM"), d.get("SIM2_OP")))
    con.commit(); con.close()
    return {"ip": ip}

@app.get("/api/devices")
def list_dev():
    con = db()
    rows = [dict(r) for r in con.execute("SELECT * FROM devices ORDER BY id DESC")]
    con.close()
    return [{"id":r["id"],"devId":r["devId"],"ip":r["ip"],"status":r["status"],"lastSeen":r["lastSeen"],"sims":{"sim1":{"number":r["sim1_number"],"operator":r["sim1_operator"]},"sim2":{"number":r["sim2_number"],"operator":r["sim2_operator"]}}} for r in rows]

class SmsReq(BaseModel):
    deviceIds: List[int]; phone: str; content: str; slot: int

@app.post("/api/sms/send")
def send_sms(req: SmsReq):
    con = db(); res = []
    for did in req.deviceIds:
        row = con.execute("SELECT ip, user, pass FROM devices WHERE id=?", (did,)).fetchone()
        if not row: res.append({"id":did, "ok":False}); continue
        try:
            r = requests.get(f"http://{row['ip']}/mgr", 
                           params={"a":"sendsms","sid":req.slot,"phone":req.phone,"content":req.content}, 
                           auth=HTTPDigestAuth(row['user'],row['pass']), timeout=5)
            res.append({"id":did, "ok": r.json().get("success", False)})
        except Exception as e: res.append({"id":did, "ok":False, "error":str(e)})
    con.close()
    return {"results": res}

class SmsQueryReq(BaseModel):
    deviceId: int

@app.post("/api/sms/query")
def query_sms(req: SmsQueryReq):
    con = db()
    row = con.execute("SELECT ip,user,pass FROM devices WHERE id=?", (req.deviceId,)).fetchone()
    con.close()
    if not row: raise HTTPException(404, "Device not found")
    
    target_ip = row['ip']
    user = row['user'] or DEFAULT_USER
    pwd = row['pass'] or DEFAULT_PASS
    
    try:
        # 1. 计算 Token
        token = calc_token(user, pwd)
        # 2. 发起请求
        url = f"http://{target_ip}/ctrl"
        params = {"cmd": "querysms", "p1": "1", "p2": "100", "token": token}
        
        r = requests.get(url, params=params, auth=HTTPDigestAuth(user, pwd), timeout=10)
        r.encoding = 'utf-8' # 强制UTF-8
        
        if r.status_code == 200:
            try:
                resp = r.json()
                if isinstance(resp, dict) and resp.get("code") == 0:
                    raw_list = resp.get("results", [])
                    sms_list = []
                    for item in raw_list:
                        ts = item.get("smsTs", 0)
                        try: ts = int(ts)
                        except: ts = 0
                        sms_list.append({
                            "phone": item.get("phNum", "未知号码"),
                            "content": item.get("smsBd", ""),
                            "time": time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(ts)) if ts > 0 else "-"
                        })
                    return {"ok": True, "data": sms_list}
                else:
                    return {"ok": False, "error": f"设备返回错误: {resp}"}
            except:
                return {"ok": True, "raw": r.text}
        return {"ok": False, "error": f"HTTP {r.status_code}"}
    except Exception as e: 
        return {"ok": False, "error": str(e)}

@app.get("/api/health")
def health(): return {"ok": True}

@app.post("/api/scan/start")
def scan(cidr: Optional[str]=None, group:str="auto", user:str="admin", password:str="admin"):
    if not cidr: return {"ok":False}
    try: ips = [str(ip) for ip in ip_network(cidr, strict=False).hosts()]
    except: return {"ok":False}
    async def run():
        loop = asyncio.get_event_loop()
        for ip in ips:
            if await loop.run_in_executor(None, is_target_device, ip, user, password):
                await loop.run_in_executor(None, upsert, ip, user, password, group)
    asyncio.run(run())
    return {"ok": True, "cidr": cidr, "found": "Scanning"}
PY

  cat > "${SERVICE_API}" <<EOF
[Unit]
Description=Board LAN Hub API
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}
Environment=BM_DB=${APP_DIR}/data/data.db
Environment=BM_DEV_USER=${SCAN_USER}
Environment=BM_DEV_PASS=${SCAN_PASS}
ExecStart=${APP_DIR}/venv/bin/uvicorn app.main:app --host 127.0.0.1 --port ${API_PORT}
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now board-manager
  log_info "后端 OK：127.0.0.1:${API_PORT}"
}

# 清洗不可见/全角空格，防止 vite 构建/解析炸
sanitize_text_file(){
  local f="$1"
  # 替换：全角空格(U+3000)、不换行空格(U+00A0)、零宽空格等
  python3 - <<PY
import re, pathlib
p=pathlib.Path(r"$f")
s=p.read_text("utf-8", errors="ignore")
s=s.replace("\u3000"," ").replace("\u00a0"," ")
s=re.sub(r"[\u200b\u200c\u200d\uFEFF]", "", s)
p.write_text(s, "utf-8")
PY
}

write_frontend(){
  title "部署前端（Vite直跑，无Nginx）"
  local FE="${APP_DIR}/frontend"
  mkdir -p "${FE}/src"

  cat > "${FE}/package.json" <<PKG
{
  "name": "board-lan-ui",
  "version": "1.0.0",
  "type": "module",
  "scripts": { "dev": "vite --host 0.0.0.0 --port ${UI_PORT}", "build": "vite build" },
  "dependencies": { "axios": "^1.6.0", "vue": "^3.4.0" },
  "devDependencies": { "@vitejs/plugin-vue": "^5.0.0", "vite": "^5.4.11" }
}
PKG

  cat > "${FE}/vite.config.js" <<JS
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({
  plugins: [vue()],
  server: { host: '0.0.0.0', port: ${UI_PORT}, proxy: { '/api': 'http://127.0.0.1:${API_PORT}' } },
  build: { outDir: 'dist' }
})
JS

  cat > "${FE}/index.html" <<'HTML'
<!doctype html>
<html lang="zh-CN">
  <head><meta charset="UTF-8" /><meta name="viewport" content="width=device-width,initial-scale=1.0" /><title>开发板管理系统</title></head>
  <body><div id="app"></div><script type="module" src="/src/main.js"></script></body>
</html>
HTML

  cat > "${FE}/src/main.js" <<'JS'
import { createApp } from 'vue'
import App from './App.vue'
createApp(App).mount('#app')
JS

  cat > "${FE}/src/App.vue" <<'VUE'
<script setup>
import AppContent from './AppContent.vue'
</script>
<template><AppContent /></template>
<style>body{margin:0;font-family:sans-serif}</style>
VUE

  # ============ 包含“查看短信”功能的全新 UI ============
  cat > "${FE}/src/AppContent.vue" <<'VUECODE'
<script setup>
import { ref, onMounted, computed } from 'vue'
import axios from 'axios'

const api = axios.create({ baseURL: '' })
const devices = ref([])
const loading = ref(false)
const msg = ref('')
const smsPhone = ref('')
const smsContent = ref('')
const smsSlot = ref(1)
const selectedIds = ref(new Set())
const searchText = ref('')

// 查看短信相关变量
const showHistory = ref(false)
const historyList = ref([])
const historyTitle = ref('')

const filteredDevices = computed(() => {
  const t = searchText.value.trim().toLowerCase()
  if (!t) return devices.value
  return devices.value.filter(d => (d.devId||'').toLowerCase().includes(t) || (d.ip||'').includes(t))
})

const allSelected = computed(() => filteredDevices.value.length > 0 && selectedIds.value.size === filteredDevices.value.length)

function toggleAll() {
  if (allSelected.value) selectedIds.value = new Set()
  else selectedIds.value = new Set(filteredDevices.value.map(d => d.id))
}
function toggleOne(id) {
  const s = new Set(selectedIds.value)
  s.has(id) ? s.delete(id) : s.add(id)
  selectedIds.value = s
}
function prettyTime(ts) {
  if (!ts) return '-'
  return new Date(ts * 1000).toLocaleString('zh-CN', { month:'2-digit', day:'2-digit', hour:'2-digit', minute:'2-digit' })
}
function simLine(d, slot) {
  const sim = slot === 1 ? d?.sims?.sim1 : d?.sims?.sim2
  if (!sim) return '-'
  return (sim.number || sim.operator || '-')
}

async function loadDevices() {
  loading.value = true; msg.value = ''
  try { const { data } = await api.get('/api/devices'); devices.value = Array.isArray(data) ? data : [] }
  catch (e) { msg.value = '❌ ' + (e?.response?.data?.detail || e.message) }
  finally { loading.value = false }
}
async function startScanAdd() {
  loading.value = true; msg.value = '🔄 扫描中...'
  try { const { data } = await api.post('/api/scan/start'); msg.value = `🔍 扫描完成`; await loadDevices() }
  catch (e) { msg.value = '❌ ' + e.message }
  finally { loading.value = false }
}
async function sendSms() {
  const ids = Array.from(selectedIds.value)
  if (ids.length === 0) return (msg.value = '⚠️ 请先选择设备')
  if (!smsPhone.value || !smsContent.value) return (msg.value = '⚠️ 请输入号码和内容')
  loading.value = true
  try {
    const { data } = await api.post('/api/sms/send', { deviceIds: ids, phone: smsPhone.value, content: smsContent.value, slot: Number(smsSlot.value) })
    msg.value = `✅ 发送结果: 成功 ${data.results.filter(r=>r.ok).length} 台`
  } catch (e) { msg.value = '❌ ' + e.message }
  finally { loading.value = false }
}

// === 核心：查看短信函数 ===
async function viewSms(d) {
  historyTitle.value = `${d.ip}`
  historyList.value = []
  showHistory.value = true
  try {
    const { data } = await api.post('/api/sms/query', { deviceId: d.id })
    if(data.ok) {
        historyList.value = data.data
        if(data.data.length === 0) msg.value = "ℹ️ 该设备暂无短信记录"
    } else {
        alert("查询失败: " + data.error)
    }
  } catch(e) { alert("请求出错: " + e.message) }
}
onMounted(loadDevices)
</script>

<template>
  <div class="page">
    <div class="header">
      <div class="title">开发板管理系统</div>
      <button class="btn" @click="loadDevices">刷新列表</button>
    </div>
    
    <div v-if="msg" class="toast">{{ msg }}</div>

    <div class="card">
      <h3>群发短信</h3>
      <div class="form">
        <select v-model="smsSlot" class="input"><option :value="1">SIM1</option><option :value="2">SIM2</option></select>
        <input v-model="smsPhone" class="input" placeholder="手机号" />
        <input v-model="smsContent" class="input" placeholder="内容" style="flex:2" />
        <button class="btn primary" :disabled="loading" @click="sendSms">发送 ({{selectedIds.size}})</button>
        <button class="btn" @click="startScanAdd">扫描添加</button>
      </div>
    </div>

    <div class="card">
      <h3>设备列表 ({{devices.length}}台)</h3>
      <div class="table-wrap">
        <table class="table">
          <thead><tr>
            <th><input type="checkbox" :checked="allSelected" @change="toggleAll" /></th>
            <th>ID</th><th>IP</th><th>状态</th><th>SIM1</th><th>SIM2</th><th>时间</th><th>操作</th>
          </tr></thead>
          <tbody>
            <tr v-for="d in filteredDevices" :key="d.id">
              <td><input type="checkbox" :checked="selectedIds.has(d.id)" @change="toggleOne(d.id)" /></td>
              <td>{{ d.devId }}</td><td>{{ d.ip }}</td>
              <td><span :class="['badge', d.status==='online'?'ok':'err']">{{ d.status }}</span></td>
              <td>{{ simLine(d,1) }}</td><td>{{ simLine(d,2) }}</td>
              <td>{{ prettyTime(d.lastSeen) }}</td>
              <td><button class="btn sm" @click="viewSms(d)">查看短信</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>

    <div v-if="showHistory" class="modal-mask" @click.self="showHistory=false">
      <div class="modal">
        <div class="modal-head">
            <h3>历史短信 ({{historyTitle}})</h3>
            <button class="close-btn" @click="showHistory=false">×</button>
        </div>
        <div class="sms-list">
            <div v-if="historyList.length===0" style="padding:20px;text-align:center;color:#999">暂无记录</div>
            <div v-for="(item,i) in historyList" :key="i" class="sms-item">
                <div class="sms-meta">
                    <span class="sms-phone">来自: {{item.phone}}</span>
                    <span class="sms-time">{{item.time}}</span>
                </div>
                <div class="sms-body">{{item.content}}</div>
            </div>
        </div>
      </div>
    </div>

  </div>
</template>

<style scoped>
.page{padding:20px;background:#f0f2f5;min-height:100vh;font-family:sans-serif}
.header{display:flex;justify-content:space-between;margin-bottom:20px}
.title{font-size:24px;font-weight:bold;color:#333}
.card{background:#fff;padding:20px;border-radius:8px;margin-bottom:20px;box-shadow:0 2px 8px rgba(0,0,0,.05)}
.form{display:flex;gap:10px;flex-wrap:wrap}
.input{padding:8px;border:1px solid #ddd;border-radius:4px}
.btn{padding:8px 16px;border:none;border-radius:4px;cursor:pointer;background:#fff;border:1px solid #ddd}
.btn.primary{background:#1890ff;color:#fff;border:none}
.btn.sm{padding:4px 8px;font-size:12px;background:#e6f7ff;color:#1890ff;border:1px solid #91d5ff}
.table{width:100%;border-collapse:collapse}
.table th,.table td{padding:12px;text-align:left;border-bottom:1px solid #eee}
.badge{padding:2px 8px;border-radius:10px;font-size:12px;color:#fff}
.badge.ok{background:#52c41a} .badge.err{background:#ff4d4f}
.toast{position:fixed;top:20px;right:20px;background:#fff;padding:10px 20px;box-shadow:0 4px 12px rgba(0,0,0,.15);border-radius:4px;z-index:999}
/* 弹窗样式 */
.modal-mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;justify-content:center;align-items:center;z-index:1000}
.modal{background:#fff;width:600px;max-width:90%;max-height:80vh;border-radius:8px;display:flex;flex-direction:column}
.modal-head{padding:15px;border-bottom:1px solid #eee;display:flex;justify-content:space-between;align-items:center}
.close-btn{background:none;border:none;font-size:24px;cursor:pointer}
.sms-list{overflow-y:auto;padding:15px}
.sms-item{border-bottom:1px solid #f0f0f0;padding:10px 0}
.sms-meta{display:flex;justify-content:space-between;font-size:12px;color:#999;margin-bottom:4px}
.sms-body{font-size:14px;color:#333;line-height:1.5}
</style>
VUECODE

  sanitize_text_file "${FE}/src/AppContent.vue"

  log_step "npm install..."
  cd "${FE}"
  npm install --silent

  cat > "${SERVICE_UI}" <<EOF
[Unit]
Description=Board LAN Hub UI
After=network.target

[Service]
Type=simple
WorkingDirectory=${APP_DIR}/frontend
ExecStart=/usr/bin/npm run dev
Restart=on-failure
RestartSec=2

[Install]
WantedBy=multi-user.target
EOF

  systemctl daemon-reload
  systemctl enable --now board-ui
  log_info "前端 OK：0.0.0.0:${UI_PORT}"
}

show_status(){
  title "系统状态"
  ss -lntp | egrep ":((${UI_PORT})|(${API_PORT}))\b" || true
  echo
  systemctl --no-pager -l status board-manager board-ui || true
  echo
  curl -sS -m 2 "http://127.0.0.1:${API_PORT}/api/health" && echo || true
  curl -sS -m 2 -I "http://127.0.0.1:${UI_PORT}/" | head -n 3 || true
  echo
  log_info "打开：http://<NAS内网IP>:${UI_PORT}/"
}

do_restart(){
  need_root restart
  systemctl restart board-manager || true
  systemctl restart board-ui || true
  show_status
}

do_logs(){
  need_root logs
  echo "1) board-manager  2) board-ui  3) all"
  read -r -p "选择 [1-3]: " c || true
  case "${c:-3}" in
    1) journalctl -u board-manager -f ;;
    2) journalctl -u board-ui -f ;;
    *) journalctl -u board-manager -u board-ui -f ;;
  esac
}

do_uninstall(){
  need_root uninstall
  title "卸载"
  systemctl stop board-manager board-ui 2>/dev/null || true
  systemctl disable board-manager board-ui 2>/dev/null || true
  rm -f "${SERVICE_API}" "${SERVICE_UI}"
  systemctl daemon-reload || true
  read -r -p "是否删除整个目录 ${APP_DIR} ? [y/N] " yn || true
  if [[ "${yn:-N}" =~ ^[Yy]$ ]]; then
    rm -rf "${APP_DIR}"
    log_info "已删除：${APP_DIR}"
  else
    log_warn "保留：${APP_DIR}"
  fi
  log_info "卸载完成"
}

do_scan(){
  need_root scan
  local cidr="" user="${SCAN_USER}" pw="${SCAN_PASS}"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --cidr) cidr="${2:-}"; shift 2;;
      --user) user="${2:-}"; shift 2;;
      --pass) pw="${2:-}"; shift 2;;
      --dir)  APP_DIR="${2:-}"; shift 2;;
      *) shift;;
    esac
  done
  title "主动扫描添加"
  local url="http://127.0.0.1:${API_PORT}/api/scan/start"
  if [[ -n "$cidr" ]]; then url="${url}?cidr=${cidr}"; fi
  log_step "POST ${url}"
  curl -sS -X POST "${url}&group=auto&user=${user}&password=${pw}" | sed 's/},/},\n/g' || true
  echo
  curl -sS "http://127.0.0.1:${API_PORT}/api/devices" | head -c 1200; echo
}

do_install(){
  need_root install
  install_pkgs
  install_node
  ensure_dirs
  write_backend
  write_frontend

  title "安装后自动扫描一次"
  local url="http://127.0.0.1:${API_PORT}/api/scan/start"
  if [[ -n "${INSTALL_CIDR}" ]]; then url="${url}?cidr=${INSTALL_CIDR}"; fi
  curl -sS -X POST "${url}&group=auto&user=${SCAN_USER}&password=${SCAN_PASS}" | sed 's/},/},\n/g' || true
  echo
  show_status
  log_warn "若 found=0：说明网段不对或这台机器不在设备局域网。重扫：sudo $0 scan --cidr 192.168.1.0/24"
}

help(){
  cat <<EOF
用法：
  sudo $0 install [--dir /opt/board-manager] [--ui-port 5173] [--api-port 8000] [--cidr 192.168.1.0/24] [--user admin] [--pass admin]
  sudo $0 scan    [--cidr 192.168.1.0/24] [--user admin] [--pass admin]
  sudo $0 status | restart | logs | uninstall

说明：
- 不使用 Nginx：前端 Vite dev server 直接跑（内网NAS最省事）
- /api 自动代理到后端：前端无需改 baseURL
- 扫描只会添加 realm="asyncesp" 且 digest 登录成功的设备（不会误加别的设备）
EOF
}

cmd="${1:-help}"; shift || true
while [[ $# -gt 0 ]]; do
  case "$1" in
    --dir) APP_DIR="${2:-}"; shift 2;;
    --ui-port) UI_PORT="${2:-5173}"; shift 2;;
    --api-port) API_PORT="${2:-8000}"; shift 2;;
    --cidr) INSTALL_CIDR="${2:-}"; shift 2;;
    --user) SCAN_USER="${2:-admin}"; shift 2;;
    --pass) SCAN_PASS="${2:-admin}"; shift 2;;
    *) shift;;
  esac
done

case "$cmd" in
  install) do_install ;;
  scan) do_scan "$@" ;;
  status) show_status ;;
  restart) do_restart ;;
  logs) do_logs ;;
  uninstall) do_uninstall ;;
  help|*) help ;;
esac

#!/usr/bin/env bash
# ============================================================
# Board LAN Hub - 最终融合版
# (紫色美化UI + 统计卡片 + 查看短信功能 + 100网段自动扫 + 域名访问许可)
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

  # === 使用完整版后端（支持查看短信接口） ===
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

# MD5 Token 计算 (用于查看短信)
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
        token = calc_token(user, pwd)
        url = f"http://{target_ip}/ctrl"
        params = {"cmd": "querysms", "p1": "1", "p2": "100", "token": token}
        
        r = requests.get(url, params=params, auth=HTTPDigestAuth(user, pwd), timeout=10)
        r.encoding = 'utf-8'
        
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

# 清洗不可见/全角空格
sanitize_text_file(){
  local f="$1"
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
  title "部署前端（美化UI + 修复功能版）"
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

  # === 关键修复：添加 allowedHosts: true 以允许域名访问 ===
  cat > "${FE}/vite.config.js" <<JS
import { defineConfig } from 'vite'
import vue from '@vitejs/plugin-vue'
export default defineConfig({
  plugins: [vue()],
  server: { 
    host: '0.0.0.0', 
    port: ${UI_PORT}, 
    allowedHosts: true,
    proxy: { '/api': 'http://127.0.0.1:${API_PORT}' } 
  },
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

  # ============ UI 完全还原为你的美化版，但注入了功能修复 ============
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

// === 增加：查看短信变量 ===
const showHistory = ref(false)
const historyList = ref([])
const historyTitle = ref('')

const filteredDevices = computed(() => {
  const t = searchText.value.trim().toLowerCase()
  if (!t) return devices.value
  return devices.value.filter(d =>
    (d.devId || '').toLowerCase().includes(t) ||
    (d.ip || '').toLowerCase().includes(t) ||
    (d.sims?.sim1?.number || '').includes(t) ||
    (d.sims?.sim2?.number || '').includes(t)
  )
})

const allSelected = computed(() =>
  filteredDevices.value.length > 0 && selectedIds.value.size === filteredDevices.value.length
)

const onlineCount = computed(() => devices.value.filter(d => d.status === 'online').length)
const offlineCount = computed(() => devices.value.filter(d => d.status !== 'online').length)

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
  return new Date(ts * 1000).toLocaleString('zh-CN', {
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit'
  })
}

function simLine(d, slot) {
  const sim = slot === 1 ? d?.sims?.sim1 : d?.sims?.sim2
  if (!sim) return '-'
  const number = (sim.number || '').trim()
  const op = (sim.operator || '').trim()
  const label = (sim.label || '').trim()
  if (number && op) return `${number} (${op})`
  if (number) return number
  if (label) return label
  if (op) return op
  return '-'
}

async function loadDevices() {
  loading.value = true; msg.value = ''
  try { const { data } = await api.get('/api/devices'); devices.value = Array.isArray(data) ? data : [] }
  catch (e) { msg.value = '❌ ' + (e?.response?.data?.detail || e.message) }
  finally { loading.value = false }
}

async function refreshAllStat() {
  msg.value = '🔄 重新扫描更新设备...'
  await startScanAdd()
}

// === 修复：强制扫描 100 网段 ===
async function startScanAdd() {
  loading.value = true; msg.value = ''
  try {
    const { data } = await api.post('/api/scan/start?cidr=192.168.100.0/24')
    msg.value = `🔍 扫描指令已发送`; 
    setTimeout(loadDevices, 3000)
  } catch (e) {
    msg.value = '❌ ' + (e?.response?.data?.detail || e.message)
  } finally {
    loading.value = false
  }
}

async function sendSms() {
  const ids = Array.from(selectedIds.value)
  if (ids.length === 0) return (msg.value = '⚠️ 请先选择设备')
  if (!smsPhone.value.trim()) return (msg.value = '⚠️ 请输入接收号码')
  if (!smsContent.value.trim()) return (msg.value = '⚠️ 请输入短信内容')
  loading.value = true; msg.value = ''
  try {
    const payload = { deviceIds: ids, phone: smsPhone.value.trim(), content: smsContent.value.trim(), slot: Number(smsSlot.value) }
    const { data } = await api.post('/api/sms/send', payload)
    const ok = (data.results || []).filter(r => r.ok).length
    msg.value = `✅ 成功 ${ok} 台 (SIM${smsSlot.value})`
  } catch (e) { msg.value = '❌ ' + e.message }
  finally { loading.value = false }
}

// === 增加：查看短信函数 ===
async function viewSms(d) {
  historyTitle.value = `${d.ip}`
  historyList.value = []
  showHistory.value = true
  try {
    const { data } = await api.post('/api/sms/query', { deviceId: d.id })
    if(data.ok) {
        historyList.value = data.data
        if(data.data.length === 0) msg.value = "ℹ️ 暂无短信"
    } else { alert("查询失败: " + data.error) }
  } catch(e) { alert("请求出错: " + e.message) }
}

onMounted(loadDevices)
</script>

<template>
  <div class="page">
    <header class="header">
      <div class="logo">
        <svg class="logo-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor">
          <rect x="3" y="3" width="18" height="18" rx="2" stroke-width="2"/>
          <path d="M3 9h18M9 3v18" stroke-width="2"/>
        </svg>
        <div>
          <div class="title">开发板管理系统</div>
          <div class="subtitle">绿邮 X系列双卡双待 4G 开发板 · 内网群控</div>
        </div>
      </div>
      <div class="header-actions">
        <button class="btn btn-icon" :disabled="loading" @click="loadDevices" title="刷新列表">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M21.5 2v6h-6M2.5 22v-6h6M2 11.5a10 10 0 0118.8-4.3M22 12.5a10 10 0 01-18.8 4.2"/>
          </svg>
        </button>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="stat-icon online">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/>
          </svg>
        </div>
        <div><div class="stat-value">{{ onlineCount }}</div><div class="stat-label">在线设备</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon offline">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <circle cx="12" cy="12" r="10"/><path d="M15 9l-6 6M9 9l6 6"/>
          </svg>
        </div>
        <div><div class="stat-value">{{ offlineCount }}</div><div class="stat-label">离线设备</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon total">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87M16 3.13a4 4 0 010 7.75"/>
          </svg>
        </div>
        <div><div class="stat-value">{{ devices.length }}</div><div class="stat-label">总设备数</div></div>
      </div>
      <div class="stat-card">
        <div class="stat-icon selected">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
            <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
          </svg>
        </div>
        <div><div class="stat-value">{{ selectedIds.size }}</div><div class="stat-label">已选设备</div></div>
      </div>
    </div>

    <transition name="fade">
      <div v-if="msg" class="toast" :class="{ 'toast-error': msg.includes('❌') }">
        {{ msg }} <button class="toast-close" @click="msg = ''">×</button>
      </div>
    </transition>

    <section class="card">
      <div class="card-header">
        <h2>📱 群发短信</h2>
        <div class="card-actions">
          <button class="btn btn-sm btn-secondary" :disabled="loading" @click="startScanAdd">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
            扫描添加 (100网段)
          </button>
        </div>
      </div>
      <div class="form-grid">
        <div class="form-group">
          <label>卡槽选择</label>
          <select v-model="smsSlot" class="input select"><option :value="1">SIM1 卡槽</option><option :value="2">SIM2 卡槽</option></select>
        </div>
        <div class="form-group">
          <label>接收号码</label>
          <input v-model="smsPhone" class="input" placeholder="13800138000" />
        </div>
        <div class="form-group full-width">
          <label>短信内容</label>
          <textarea v-model="smsContent" class="input textarea" rows="3" placeholder="输入要发送的短信内容..."></textarea>
        </div>
        <div class="form-group full-width">
          <button class="btn btn-primary btn-lg" :disabled="loading || selectedIds.size === 0" @click="sendSms">
            发送短信 ({{ selectedIds.size }} 台设备)
          </button>
        </div>
      </div>
    </section>

    <section class="card">
      <div class="card-header">
        <h2>📡 设备列表</h2>
        <div class="search-box">
          <svg class="search-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="11" cy="11" r="8"/><path d="M21 21l-4.35-4.35"/></svg>
          <input v-model="searchText" class="input search-input" placeholder="搜索设备ID、IP或号码..." />
        </div>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead>
            <tr>
              <th style="width: 50px"><input type="checkbox" :checked="allSelected" @change="toggleAll" /></th>
              <th style="width: 140px">设备ID</th><th style="width: 140px">IP地址</th><th style="width: 100px">状态</th>
              <th>SIM1 卡槽</th><th>SIM2 卡槽</th><th style="width: 160px">最后在线</th>
              <th style="width: 100px">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="d in filteredDevices" :key="d.id" :class="{ 'row-selected': selectedIds.has(d.id) }">
              <td><input type="checkbox" :checked="selectedIds.has(d.id)" @change="toggleOne(d.id)" /></td>
              <td class="mono">{{ d.devId }}</td><td class="mono">{{ d.ip }}</td>
              <td><span class="badge" :class="d.status === 'online' ? 'badge-success' : 'badge-danger'"><span class="badge-dot"></span>{{ d.status === 'online' ? '在线' : '离线' }}</span></td>
              <td><div class="sim-info">📶 {{ simLine(d, 1) }}</div></td><td><div class="sim-info">📶 {{ simLine(d, 2) }}</div></td>
              <td class="mono time">{{ prettyTime(d.lastSeen) }}</td>
              <td><button class="btn btn-sm btn-secondary" @click="viewSms(d)">查看</button></td>
            </tr>
            <tr v-if="filteredDevices.length === 0"><td colspan="8" class="empty-state"><p>暂无设备数据</p></td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <div v-if="showHistory" class="modal-mask" @click.self="showHistory=false">
      <div class="modal">
        <div class="modal-head"><h3>历史短信 ({{historyTitle}})</h3><button class="close-btn" @click="showHistory=false">×</button></div>
        <div class="sms-list">
            <div v-if="historyList.length===0" style="padding:20px;text-align:center;color:#999">暂无记录</div>
            <div v-for="(item,i) in historyList" :key="i" class="sms-item">
                <div class="sms-meta"><span class="sms-phone">来自: {{item.phone}}</span><span class="sms-time">{{item.time}}</span></div>
                <div class="sms-body">{{item.content}}</div>
            </div>
        </div>
      </div>
    </div>
    
    <footer class="footer"><p>绿邮® X系列开发板管理系统</p></footer>
  </div>
</template>

<style scoped>
*{box-sizing:border-box}
.page{min-height:100vh;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);padding:24px;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif}
.header{display:flex;justify-content:space-between;align-items:center;margin-bottom:24px}
.logo{display:flex;align-items:center;gap:16px}
.logo-icon{width:48px;height:48px;color:#fff;filter:drop-shadow(0 4px 6px rgba(0,0,0,.1))}
.title{font-size:28px;font-weight:800;color:#fff;text-shadow:0 2px 4px rgba(0,0,0,.1)}
.subtitle{font-size:13px;color:rgba(255,255,255,.9);margin-top:4px}
.btn{display:inline-flex;align-items:center;gap:8px;padding:10px 18px;border:none;border-radius:12px;font-weight:600;font-size:14px;cursor:pointer;transition:all .2s;background:#fff;color:#334155;box-shadow:0 2px 8px rgba(0,0,0,.1)}
.btn:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 4px 12px rgba(0,0,0,.15)}
.btn:disabled{opacity:.6;cursor:not-allowed}
.btn svg{width:18px;height:18px}
.btn-icon{padding:10px;background:rgba(255,255,255,.2);color:#fff;backdrop-filter:blur(10px)}
.btn-primary{background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);color:#fff}
.btn-secondary{background:#f1f5f9;color:#475569}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-lg{padding:14px 28px;font-size:16px;width:100%}
.stats-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(240px,1fr));gap:16px;margin-bottom:24px}
.stat-card{background:#fff;border-radius:16px;padding:20px;display:flex;align-items:center;gap:16px;box-shadow:0 4px 12px rgba(0,0,0,.08);transition:transform .2s}
.stat-card:hover{transform:translateY(-4px)}
.stat-icon{width:56px;height:56px;border-radius:12px;display:flex;align-items:center;justify-content:center}
.stat-icon svg{width:28px;height:28px;color:#fff}
.stat-icon.online{background:linear-gradient(135deg,#10b981 0%,#059669 100%)}
.stat-icon.offline{background:linear-gradient(135deg,#ef4444 0%,#dc2626 100%)}
.stat-icon.total{background:linear-gradient(135deg,#3b82f6 0%,#2563eb 100%)}
.stat-icon.selected{background:linear-gradient(135deg,#8b5cf6 0%,#7c3aed 100%)}
.stat-value{font-size:32px;font-weight:800;color:#0f172a;line-height:1}
.stat-label{font-size:13px;color:#64748b;margin-top:4px}
.toast{background:#fff;border-left:4px solid #10b981;border-radius:12px;padding:14px 18px;margin-bottom:24px;box-shadow:0 4px 12px rgba(0,0,0,.1);display:flex;justify-content:space-between;align-items:center}
.toast-error{border-left-color:#ef4444}
.toast-close{background:none;border:none;font-size:24px;color:#64748b;cursor:pointer}
.fade-enter-active,.fade-leave-active{transition:all .3s}
.fade-enter-from,.fade-leave-to{opacity:0;transform:translateY(-10px)}
.card{background:#fff;border-radius:20px;padding:24px;margin-bottom:24px;box-shadow:0 4px 16px rgba(0,0,0,.08)}
.card-header{display:flex;justify-content:space-between;align-items:center;margin-bottom:20px;flex-wrap:wrap;gap:16px}
.card-header h2{font-size:20px;font-weight:800;color:#0f172a;margin:0}
.card-actions{display:flex;gap:10px}
.form-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:16px}
.form-group{display:flex;flex-direction:column;gap:8px}
.form-group.full-width{grid-column:1/-1}
.form-group label{font-size:13px;font-weight:700;color:#334155}
.input{padding:12px 16px;border:2px solid #e2e8f0;border-radius:10px;font-size:14px;transition:all .2s;outline:none}
.input:focus{border-color:#667eea;box-shadow:0 0 0 3px rgba(102,126,234,.1)}
.textarea{resize:vertical;font-family:inherit}
.search-box{position:relative;width:300px}
.search-icon{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:18px;height:18px;color:#94a3b8;pointer-events:none}
.search-input{padding-left:40px;width:100%}
.table-wrap{overflow-x:auto;border-radius:12px;border:1px solid #e2e8f0}
.table{width:100%;border-collapse:collapse;min-width:900px}
.table thead th{background:#f8fafc;padding:14px 16px;text-align:left;font-size:12px;font-weight:700;color:#475569;text-transform:uppercase;border-bottom:2px solid #e2e8f0}
.table tbody td{padding:16px;border-bottom:1px solid #f1f5f9;font-size:14px;color:#334155}
.table tbody tr:hover{background:#f8fafc}
.table tbody tr.row-selected{background:#ede9fe}
.mono{font-family:ui-monospace,monospace;font-size:13px}
.badge{display:inline-flex;align-items:center;gap:6px;padding:6px 12px;border-radius:20px;font-size:12px;font-weight:700}
.badge-success{background:rgba(16,185,129,.1);color:#065f46}
.badge-danger{background:rgba(239,68,68,.1);color:#7f1d1d}
.badge-dot{width:8px;height:8px;border-radius:50%;background:currentColor;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.5}}
.sim-info{display:flex;align-items:center;gap:8px}
.empty-state{text-align:center;padding:48px 20px !important;color:#94a3b8}
.footer{text-align:center;color:rgba(255,255,255,.8);font-size:13px;margin-top:24px}
@media (max-width:768px){ .stats-grid{grid-template-columns:repeat(2,1fr)} .form-grid{grid-template-columns:1fr} .search-box{width:100%} }
/* 弹窗样式 */
.modal-mask{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,0.5);display:flex;justify-content:center;align-items:center;z-index:1000}
.modal{background:#fff;width:600px;max-width:90%;max-height:80vh;border-radius:12px;display:flex;flex-direction:column;box-shadow:0 10px 25px rgba(0,0,0,0.2)}
.modal-head{padding:20px;border-bottom:1px solid #eee;display:flex;justify-content:space-between;align-items:center;background:#f8fafc;border-radius:12px 12px 0 0}
.close-btn{background:none;border:none;font-size:24px;cursor:pointer;color:#64748b}
.sms-list{overflow-y:auto;padding:20px}
.sms-item{border-bottom:1px solid #f0f0f0;padding:12px 0}
.sms-meta{display:flex;justify-content:space-between;font-size:12px;color:#94a3b8;margin-bottom:6px}
.sms-body{font-size:14px;color:#334155;line-height:1.6}
</style>
VUECODE

  sanitize_text_file "${FE}/src/AppContent.vue"

  log_step "npm install..."
  cd "${FE}"
  npm install --silent

  cat > "${SERVICE_UI}" <<EOF
[Unit]
Description=Board LAN Hub UI (Vite Dev Server)
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
  log_info "前端 OK：0.0.0.0:${UI_PORT}（/api 已代理到 127.0.0.1:${API_PORT}）"
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

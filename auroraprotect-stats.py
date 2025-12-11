# Aurora Protect Tenant Stats
# By: Matthew Chapman
# Version: 1.11

import tkinter as tk
from tkinter import messagebox, ttk, filedialog
import jwt
import uuid
import requests
import datetime
from datetime import timedelta
import json
import pandas as pd
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import threading
from queue import Queue
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import os

# ---------- CONFIG / GLOBALS ----------
DEBUG = False
MAX_WORKERS = 8  # for concurrent device threat fetching
THREAT_FETCH_TIMEOUT = 30  # seconds for individual threat GETs

logging.basicConfig(level=logging.DEBUG if DEBUG else logging.INFO,
                    format='%(asctime)s %(levelname)s: %(message)s')
log = logging.getLogger("AuroraMT")

# ---------- Utility functions ----------

def normalize_items(data):
    """Return a list of items from various possible API shapes."""
    if not isinstance(data, dict):
        return []
    return data.get("page_items") or data.get("items") or data.get("data") or data.get("results") or []


def safe_get(d, *keys, default="N/A"):
    for k in keys:
        if isinstance(d, dict) and k in d:
            return d[k]
    return default


# ---------- API helpers ----------
class CylanceAPI:
    def __init__(self):
        self.session = requests.Session()
        self.token = None
        self.token_obtained_at = None

    def get_cylance_token(self, tenant_id, app_id, app_secret, region_url):
        now = datetime.datetime.utcnow()
        timeout = 1800  # 30 minutes
        epoch_time = int((now - datetime.datetime(1970, 1, 1)).total_seconds())
        epoch_timeout = int((now + timedelta(seconds=timeout) - datetime.datetime(1970, 1, 1)).total_seconds())
        jti_val = str(uuid.uuid4())

        payload = {
            "exp": epoch_timeout,
            "iat": epoch_time,
            "iss": "http://cylance.com",
            "sub": app_id,
            "tid": tenant_id,
            "jti": jti_val,
        }

        if DEBUG:
            log.debug("JWT payload: %s", payload)

        jwt_token = jwt.encode(payload, app_secret.strip(), algorithm='HS256')
        if isinstance(jwt_token, bytes):
            jwt_token = jwt_token.decode('utf-8')

        auth_url = f"{region_url}/auth/v2/token"
        headers = {"Content-Type": "application/json; charset=utf-8"}
        body = {"auth_token": jwt_token}

        resp = self.session.post(auth_url, headers=headers, json=body, timeout=30)
        resp.raise_for_status()
        self.token = resp.json().get("access_token")
        self.token_obtained_at = datetime.datetime.utcnow()
        # store bearer in session headers for convenience
        self.session.headers.update({"Authorization": f"Bearer {self.token}", "Accept": "application/json"})
        return self.token

    def get(self, endpoint, region_url, timeout=30):
        url = f"{region_url.rstrip('/')}/{endpoint.lstrip('/') }"
        try:
            resp = self.session.get(url, timeout=timeout)
            resp.raise_for_status()
            return resp.json()
        except requests.RequestException as e:
            # attach response text when available
            txt = getattr(e.response, 'text', None) if hasattr(e, 'response') else None
            log.error("Request error for %s: %s (resp=%s)", endpoint, e, txt)
            return {"error": str(e)}
        except json.JSONDecodeError as e:
            log.error("JSON decode error for %s: %s", endpoint, e)
            return {"error": str(e)}


# ---------- Main GUI class ----------
class CylanceGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Aurora Protect Tenant Stats")
        self.root.geometry("900x650")

        self.tenants = self.load_tenants()
        self.api = CylanceAPI()
        self.selected_tenant = None
        self.data = None
        self.devices_data = None
        self.detection_data = []
        self.fetching = False
        self.error_queue = Queue()
        self.cancel_event = threading.Event()
        self.device_threats_cache = {}  # device_id -> threats list

        # Top controls
        top_frame = ttk.Frame(root)
        top_frame.pack(fill=tk.X, padx=8, pady=6)

        ttk.Label(top_frame, text="Select Tenant:").pack(side=tk.LEFT)
        tenant_names = list(self.tenants.keys()) if self.tenants else ["(no tenants)"]
        self.tenant_var = tk.StringVar(value=tenant_names[0])
        self.tenant_menu = ttk.OptionMenu(top_frame, self.tenant_var, tenant_names[0], *tenant_names)
        self.tenant_menu.pack(side=tk.LEFT, padx=6)

        self.connect_btn = ttk.Button(top_frame, text="Connect", command=self.connect_tenant)
        self.connect_btn.pack(side=tk.LEFT, padx=4)

        self.cancel_btn = ttk.Button(top_frame, text="Cancel Fetch", command=self.cancel_fetch)
        self.cancel_btn.pack(side=tk.LEFT, padx=4)
        self.cancel_btn.config(state=tk.DISABLED)

        # Fetch buttons
        button_frame = ttk.Frame(root)
        button_frame.pack(pady=6)
        self.fetch_buttons = []
        endpoints = [("Get Threats", "threats/v2"), ("Get Devices", "devices/v2"), ("Get Users", "users/v2"), ("Get Detections", "detections/v2")]
        for text, ep in endpoints:
            b = ttk.Button(button_frame, text=text, command=lambda e=ep: self.fetch_data(e))
            b.pack(side=tk.LEFT, padx=4)
            self.fetch_buttons.append(b)

        ttk.Button(root, text="Export to Excel", command=self.export_excel).pack(pady=6)

        # Treeview and search
        search_frame = ttk.Frame(root)
        search_frame.pack(fill=tk.X, padx=8)
        ttk.Label(search_frame, text="Filter:").pack(side=tk.LEFT)
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', lambda *a: self.apply_filter())
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=40)
        self.search_entry.pack(side=tk.LEFT, padx=6)

        self.tree = ttk.Treeview(root, show="headings")
        self.tree.pack(fill="both", expand=True, padx=8, pady=8)

        self.progress = ttk.Progressbar(root, orient="horizontal", length=300, mode="determinate")
        self.progress.pack(pady=4)

        ttk.Button(root, text="Show Graphs", command=self.show_graphs).pack(pady=4)

        self.root.after(100, self.check_error_queue)

        # columns mapping for reuse
        self.COLUMNS = {
            "threats": [("Name", 250), ("Classification", 150), ("Last Found", 150), ("Remediation", 120)],
            "devices": [("ID", 100), ("Name", 200), ("Status", 100), ("Agent Version", 120), ("OS Version", 150), ("Quarantined Count", 150)],
            "users": [("ID", 150), ("Name", 150), ("Email", 200), ("Last Login", 150)],
            "detections": [("ID", 150), ("Severity", 100), ("Status", 100), ("Device ID", 150), ("Device Name", 150), ("Created At", 150), ("Detection Description", 250)],
        }

    def load_tenants(self):
        try:
            with open("tenants.json", "r") as f:
                return json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load tenants.json: {e}")
            return {}

    def connect_tenant(self):
        tenant_name = self.tenant_var.get()
        tenant = self.tenants.get(tenant_name)
        if not tenant:
            messagebox.showerror("Error", "Selected tenant not found")
            return
        try:
            token = self.api.get_cylance_token(tenant["tenant_id"], tenant["app_id"], tenant["app_secret"], tenant["region"])
            self.selected_tenant = tenant
            messagebox.showinfo("Success", f"Connected to {tenant_name}")
        except Exception as e:
            log.exception("Failed to connect")
            messagebox.showerror("Connection Failed", str(e))

    def check_error_queue(self):
        while not self.error_queue.empty():
            error = self.error_queue.get()
            messagebox.showerror("Error", error)
        self.root.after(100, self.check_error_queue)

    def set_columns(self, which):
        cols = self.COLUMNS.get(which, [])
        col_ids = [c[0] for c in cols]
        self.tree.config(columns=col_ids)
        for c, w in cols:
            self.tree.heading(c, text=c)
            self.tree.column(c, width=w)

    def apply_filter(self):
        filter_text = self.search_var.get().lower()
        for iid in self.tree.get_children():
            vals = " ".join(map(str, self.tree.item(iid, 'values'))).lower()
            if filter_text in vals:
                self.tree.reattach(iid, '', 'end')
            else:
                self.tree.detach(iid)

    def disable_controls(self):
        for b in self.fetch_buttons:
            b.config(state=tk.DISABLED)
        self.connect_btn.config(state=tk.DISABLED)
        self.cancel_btn.config(state=tk.NORMAL)

    def enable_controls(self):
        for b in self.fetch_buttons:
            b.config(state=tk.NORMAL)
        self.connect_btn.config(state=tk.NORMAL)
        self.cancel_btn.config(state=tk.DISABLED)

    def cancel_fetch(self):
        if self.fetching:
            self.cancel_event.set()
            log.info("Cancel requested")

    def fetch_data(self, endpoint):
        if not self.api.token:
            messagebox.showerror("Error", "Please connect to a tenant first.")
            return
        if self.fetching:
            messagebox.showerror("Error", "A fetch is already running.")
            return

        self.fetching = True
        self.cancel_event.clear()
        self.device_threats_cache.clear()
        self.data = None
        self.tree.delete(*self.tree.get_children())
        self.progress['value'] = 0
        self.progress['maximum'] = 100
        self.disable_controls()

        def worker():
            try:
                region = self.selected_tenant['region']
                resp = self.api.get(endpoint, region)
                self.data = resp

                # store devices likewise when needed
                if 'devices' in endpoint:
                    self.devices_data = resp
                if 'detections' in endpoint:
                    self.detection_data = normalize_items(resp)

                # setup columns
                if 'threats' in endpoint:
                    self.root.after(0, lambda: self.set_columns('threats'))
                elif 'devices' in endpoint:
                    self.root.after(0, lambda: self.set_columns('devices'))
                elif 'users' in endpoint:
                    self.root.after(0, lambda: self.set_columns('users'))
                elif 'detections' in endpoint:
                    self.root.after(0, lambda: self.set_columns('detections'))

                items = normalize_items(resp)
                if not items:
                    self.root.after(0, lambda: self.tree.insert('', 'end', values=("No data available",)))
                    return

                batch_size = max(1, len(items) // 50)

                # specialized processing for endpoints that need extra API calls
                if 'threats' in endpoint:
                    # ensure we have devices cached for remediation lookup
                    if not self.devices_data or not normalize_items(self.devices_data):
                        self.devices_data = self.api.get('devices/v2', region)
                    # process threats with remediation lookup (parallel for device threats)
                    self.process_threats(items, region)
                elif 'devices' in endpoint:
                    # fetch threats per device in a bounded threadpool
                    self.process_devices(items, region)
                elif 'users' in endpoint:
                    for i, item in enumerate(items):
                        if self.cancel_event.is_set():
                            log.info('Fetch cancelled')
                            break
                        vals = self.format_user_row(item)
                        self.root.after(0, lambda v=vals: self.tree.insert('', 'end', values=v))
                        progress = int((i+1)/len(items)*100)
                        self.root.after(0, lambda p=progress: self.progress.config(value=p))
                elif 'detections' in endpoint:
                    for i, item in enumerate(items):
                        if self.cancel_event.is_set():
                            log.info('Fetch cancelled')
                            break
                        vals, severity = self.format_detection_row(item)
                        self.root.after(0, lambda v=vals, s=severity: self.tree.insert('', 'end', values=v, tags=(s,)))
                        progress = int((i+1)/len(items)*100)
                        self.root.after(0, lambda p=progress: self.progress.config(value=p))

                # set color tags for detections
                self.root.after(0, lambda: self.tree.tag_configure('Low', background='#90EE90'))
                self.root.after(0, lambda: self.tree.tag_configure('Medium', background='#FFFF99'))
                self.root.after(0, lambda: self.tree.tag_configure('High', background='#FF9999'))

            except Exception as e:
                log.exception('Error in fetch worker')
                self.error_queue.put(str(e))
            finally:
                self.fetching = False
                self.root.after(0, lambda: self.progress.config(value=100))
                self.root.after(0, self.enable_controls)

        threading.Thread(target=worker, daemon=True).start()

    # ---------- Formatting helpers ----------
    def format_user_row(self, item):
        name = f"{item.get('first_name','')} {item.get('last_name','')}".strip() or 'N/A'
        last_login = item.get('date_last_login', 'Never')
        return [item.get('user_id', item.get('id', 'N/A')), name, item.get('email', 'N/A'), last_login]

    def format_detection_row(self, item):
        device = item.get('Device', {}) if isinstance(item, dict) else {}
        severity = item.get('Severity', 'N/A').capitalize() if item.get('Severity') else 'N/A'
        vals = [item.get('Id', item.get('id', 'N/A')), severity, item.get('Status', 'N/A'), device.get('CylanceId', 'N/A'), device.get('Name', 'N/A'), item.get('OccurrenceTime', 'N/A'), item.get('DetectionDescription', 'N/A')]
        return vals, severity

    def format_threat_row(self, threat_item, remediation='Unknown'):
        return [threat_item.get('name','N/A'), threat_item.get('classification', threat_item.get('family','N/A')), threat_item.get('last_found','N/A'), remediation]

    # ---------- Processing heavy endpoints ----------
    def process_devices(self, items, region):
        total = len(items)
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            future_to_device = {}
            for device in items:
                if self.cancel_event.is_set():
                    break
                device_id = device.get('id')
                # schedule threat fetch
                future = ex.submit(self.fetch_device_threats, device_id, region)
                future_to_device[future] = device

            completed = 0
            for fut in as_completed(future_to_device.keys()):
                device = future_to_device[fut]
                try:
                    threats = fut.result()
                except Exception as e:
                    log.exception('Error fetching threats for device')
                    threats = []
                quarantined_count = sum(1 for t in threats if t.get('file_status') == 'Quarantined') if isinstance(threats, list) else 'Error'
                vals = [device.get('id','N/A'), device.get('name','N/A'), device.get('state','N/A'), device.get('agent_version','N/A'), device.get('os_kernel_version','N/A'), str(quarantined_count)]
                self.root.after(0, lambda v=vals: self.tree.insert('', 'end', values=v))
                completed += 1
                progress = int(completed/total*100)
                self.root.after(0, lambda p=progress: self.progress.config(value=p))
                if self.cancel_event.is_set():
                    break

    def process_threats(self, items, region):
        # We'll map sha256 -> remediation using a limited set of device threats to avoid huge fanout.
        # Strategy: pick up to N devices (or all if few) to build a threat map, then for remainder show Unknown.
        device_items = normalize_items(self.devices_data) if self.devices_data else []
        threat_map = {}
        sample_devices = device_items[:MAX_WORKERS * 2]

        # gather threats from sample devices in parallel
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
            futures = [ex.submit(self.fetch_device_threats, d.get('id'), region) for d in sample_devices if d.get('id')]
            for fut in as_completed(futures):
                try:
                    dt = fut.result()
                    for t in dt:
                        sha = t.get('sha256')
                        if sha:
                            threat_map.setdefault(sha, t.get('file_status', 'Unknown'))
                except Exception:
                    continue

        # now render threats
        for i, t in enumerate(items):
            if self.cancel_event.is_set():
                break
            remediation = threat_map.get(t.get('sha256'), 'Unknown')
            vals = self.format_threat_row(t, remediation)
            self.root.after(0, lambda v=vals: self.tree.insert('', 'end', values=v))
            progress = int((i+1)/len(items)*100)
            self.root.after(0, lambda p=progress: self.progress.config(value=p))

    def fetch_device_threats(self, device_id, region):
        if not device_id:
            return []
        # cache first
        if device_id in self.device_threats_cache:
            return self.device_threats_cache[device_id]
        endpoint = f"devices/v2/{device_id}/threats"
        resp = self.api.get(endpoint, region, timeout=THREAT_FETCH_TIMEOUT)
        items = normalize_items(resp)
        self.device_threats_cache[device_id] = items
        return items

    # ---------- Export / Graphs ----------
    def export_excel(self):
        if not self.data:
            messagebox.showerror("Error", "No data to export.")
            return
        filename = filedialog.asksaveasfilename(defaultextension=".xlsx", filetypes=[("Excel files", "*.xlsx"), ("CSV files", "*.csv")])
        if not filename:
            return
        try:
            items = normalize_items(self.data)
            if isinstance(items, list):
                df = pd.json_normalize(items)
            else:
                df = pd.json_normalize(self.data)
            if filename.endswith('.csv'):
                df.to_csv(filename, index=False)
            else:
                df.to_excel(filename, index=False)
            messagebox.showinfo("Export Successful", f"Data exported to {filename}")
        except Exception as e:
            log.exception('Export failed')
            messagebox.showerror("Export Failed", str(e))

    def show_graphs(self):
        graph_window = tk.Toplevel(self.root)
        graph_window.title("Detection Statistics")
        graph_window.geometry("800x400")

        severity_counts = {'Low': 0, 'Medium': 0, 'High': 0}
        for item in self.detection_data:
            severity = (item.get('Severity') or 'N/A').capitalize()
            if severity in severity_counts:
                severity_counts[severity] += 1

        dates = {}
        for item in self.detection_data:
            ot = item.get('OccurrenceTime') or ''
            date = ot[:10] if len(ot) >= 10 else 'N/A'
            if date != 'N/A':
                dates[date] = dates.get(date, 0) + 1

        # Bar chart (one plot per requirement of python_user_visible tool if used)
        fig_bar = Figure(figsize=(4, 3), dpi=100)
        ax_bar = fig_bar.add_subplot(111)
        ax_bar.bar(list(severity_counts.keys()), list(severity_counts.values()))
        ax_bar.set_title('Detections by Severity')
        ax_bar.set_xlabel('Severity')
        ax_bar.set_ylabel('Count')

        fig_line = Figure(figsize=(4, 3), dpi=100)
        ax_line = fig_line.add_subplot(111)
        ax_line.plot(list(dates.keys()), list(dates.values()), marker='o')
        ax_line.set_title('Detections Over Time')
        ax_line.set_xlabel('Date')
        ax_line.set_ylabel('Count')
        ax_line.tick_params(axis='x', rotation=45)

        canvas_bar = FigureCanvasTkAgg(fig_bar, master=graph_window)
        canvas_bar.draw()
        canvas_bar.get_tk_widget().pack(side=tk.LEFT, padx=10)

        canvas_line = FigureCanvasTkAgg(fig_line, master=graph_window)
        canvas_line.draw()
        canvas_line.get_tk_widget().pack(side=tk.LEFT, padx=10)


if __name__ == '__main__':
    root = tk.Tk()
    app = CylanceGUI(root)
    root.mainloop()

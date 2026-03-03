import sys
import os
import threading
import re
import logging
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ==========================================
# 核心内核适配引擎
# ==========================================
def get_kernel_entry(module_name):
    try:
        mod = __import__(f"sipvicious.{module_name}", fromlist=['*'])
        for func_name in ['run', 'Main', 'main']:
            if hasattr(mod, func_name):
                return getattr(mod, func_name)
        return None
    except Exception:
        return None

svmap_kernel = get_kernel_entry("svmap")
svwar_kernel = get_kernel_entry("svwar")
svcrack_kernel = get_kernel_entry("svcrack")

class SIPViciousFinalBossV4:
    def __init__(self, root):
        self.root = root
        self.root.title("SIPVicious 审计工具")
        self.root.geometry("750x950")
        self.root.configure(bg="#f5f5f5")
        
        self.found_ips = []
        self.is_running = False 
        
        self.setup_styles()
        self.notebook = ttk.Notebook(root)
        self.notebook.pack(expand=True, fill='both', padx=10, pady=10)
        
        self.tab_map = tk.Frame(self.notebook, bg="#ffffff")
        self.tab_war = tk.Frame(self.notebook, bg="#ffffff")
        self.tab_crack = tk.Frame(self.notebook, bg="#ffffff")
        
        self.notebook.add(self.tab_map, text="  探测 (SVMap)  ")
        self.notebook.add(self.tab_war, text="  扫号 (SVWar)  ")
        self.notebook.add(self.tab_crack, text="  审计 (SVCrack)  ")
        
        self.setup_map_ui()
        self.setup_war_ui()
        self.setup_crack_ui()
        self.setup_common_log()

    def setup_styles(self):
        style = ttk.Style()
        try: style.theme_use('vista')
        except: style.theme_use('clam')
        style.configure("TLabelframe", background="#ffffff")
        style.configure("TLabelframe.Label", font=('Segoe UI', 10, 'bold'))

    def setup_map_ui(self):
        container = tk.Frame(self.tab_map, bg="#ffffff", padx=20, pady=10)
        container.pack(fill="both")
        cfg = ttk.LabelFrame(container, text=" 探测参数设置 ", padding=15)
        cfg.pack(fill="x")

        grid_opts = {'padx': 10, 'pady': 10, 'sticky': 'w'}
        ttk.Label(cfg, text="目标网段:").grid(row=0, column=0, **grid_opts)
        self.map_target = ttk.Entry(cfg, width=25); self.map_target.insert(0, "192.168.0.0/24"); self.map_target.grid(row=0, column=1, **grid_opts)
        ttk.Label(cfg, text="目标端口:").grid(row=0, column=2, **grid_opts)
        self.map_port = ttk.Entry(cfg, width=15); self.map_port.insert(0, "5060"); self.map_port.grid(row=0, column=3, **grid_opts)

        ttk.Label(cfg, text="本地端口:").grid(row=1, column=0, **grid_opts)
        self.map_lport = ttk.Entry(cfg, width=25); self.map_lport.insert(0, "5062"); self.map_lport.grid(row=1, column=1, **grid_opts)
        ttk.Label(cfg, text="超时时间:").grid(row=1, column=2, **grid_opts)
        self.map_timeout = ttk.Entry(cfg, width=15); self.map_timeout.insert(0, "0.005"); self.map_timeout.grid(row=1, column=3, **grid_opts)

        self.map_prog = ttk.Progressbar(container, orient="horizontal", mode="determinate")
        self.map_prog.pack(fill="x", pady=(20, 5))
        self.status_var = tk.StringVar(value="准备就绪")
        tk.Label(container, textvariable=self.status_var, font=("Segoe UI", 9), fg="#666666", bg="#ffffff").pack()

        btn_frame = tk.Frame(container, bg="#ffffff"); btn_frame.pack(pady=15)
        btn_s = {'width': 18, 'font': ('Segoe UI', 10, 'bold'), 'relief': 'groove', 'cursor': 'hand2'}
        self.btn_map_run = tk.Button(btn_frame, text="▶ 开始探测", bg="#e3f2fd", fg="#1976d2", command=lambda: self.run_task("map"), **btn_s)
        self.btn_map_run.grid(row=0, column=0, padx=15)
        tk.Button(btn_frame, text="🛑 停止扫描", bg="#ffebee", fg="#d32f2f", command=self.stop_task, **btn_s).grid(row=0, column=1, padx=15)

        link_frame = tk.Frame(container, bg="#fcfcfc", highlightbackground="#eeeeee", highlightthickness=1, padx=15, pady=15)
        link_frame.pack(fill="x", pady=10)
        ttk.Label(link_frame, text="发现的 SIP 设备:", background="#fcfcfc").pack(side="left")
        self.ip_list = ttk.Combobox(link_frame, values=[], width=35, state="readonly")
        self.ip_list.pack(side="left", padx=15)
        tk.Button(link_frame, text="同步到分机枚举 ➔", bg="#f3e5f5", command=self.link_to_war).pack(side="left")

    def setup_war_ui(self):
        container = tk.Frame(self.tab_war, bg="#ffffff", padx=25, pady=25)
        container.pack(fill="both")
        cfg = ttk.LabelFrame(container, text=" 分机枚举参数 ", padding=15)
        cfg.pack(fill="x")
        grid_opts = {'padx': 10, 'pady': 10, 'sticky': 'w'}
        ttk.Label(cfg, text="目标主机 IP:").grid(row=0, column=0, **grid_opts)
        self.war_target = ttk.Entry(cfg, width=35); self.war_target.grid(row=0, column=1, **grid_opts)
        ttk.Label(cfg, text="枚举范围:").grid(row=1, column=0, **grid_opts)
        self.war_ext = ttk.Entry(cfg, width=35); self.war_ext.insert(0, "100-500"); self.war_ext.grid(row=1, column=1, **grid_opts)
        tk.Button(container, text="🔍 开始扫号", bg="#e8f5e9", width=20, font=('Segoe UI', 10, 'bold'), command=lambda: self.run_task("war")).pack(pady=20)

    def setup_crack_ui(self):
        container = tk.Frame(self.tab_crack, bg="#ffffff", padx=25, pady=25)
        container.pack(fill="both")
        cfg = ttk.LabelFrame(container, text=" 密码审计参数 ", padding=15)
        cfg.pack(fill="x")
        grid_opts = {'padx': 10, 'pady': 10, 'sticky': 'w'}
        ttk.Label(cfg, text="目标主机 IP:").grid(row=0, column=0, **grid_opts)
        self.crack_target = ttk.Entry(cfg, width=35); self.crack_target.grid(row=0, column=1, **grid_opts)
        ttk.Label(cfg, text="目标分机号:").grid(row=1, column=0, **grid_opts)
        self.crack_user = ttk.Entry(cfg, width=35); self.crack_user.insert(0, "100"); self.crack_user.grid(row=1, column=1, **grid_opts)
        ttk.Label(cfg, text="密码范围:").grid(row=2, column=0, **grid_opts)
        self.crack_pass = ttk.Entry(cfg, width=35); self.crack_pass.insert(0, "100-9999"); self.crack_pass.grid(row=2, column=1, **grid_opts)
        tk.Button(container, text="🔑 开始审计", bg="#fff3e0", width=20, font=('Segoe UI', 10, 'bold'), command=lambda: self.run_task("crack")).pack(pady=20)

    def setup_common_log(self):
        log_frame = tk.Frame(self.root, bg="#f5f5f5", padx=15, pady=10)
        log_frame.pack(fill="both", expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, bg="#ffffff", fg="#333333", font=("Consolas", 10))
        self.log_area.pack(fill="both", expand=True)

    def link_to_war(self):
        ip = self.ip_list.get().split(':')[0].strip()
        if ip:
            self.war_target.delete(0, tk.END); self.war_target.insert(0, ip)
            self.crack_target.delete(0, tk.END); self.crack_target.insert(0, ip)
            self.notebook.select(1)

    def stop_task(self):
        self.is_running = False
        self.status_var.set("任务已中止")

    def run_task(self, mode):
        if self.is_running: return
        mapping = {"map": svmap_kernel, "war": svwar_kernel, "crack": svcrack_kernel}
        func = mapping.get(mode)
        
        if not func:
            messagebox.showerror("运行失败", f"内核 {mode} 模块未识别。")
            return

        if mode == "map":
            args = ['svmap.py', self.map_target.get(), '-p', self.map_port.get(), '-P', self.map_lport.get(), '-t', self.map_timeout.get(), '-A', '-vv']
        elif mode == "war":
            args = ['svwar.py', self.war_target.get(), '-e', self.war_ext.get(), '-v']
        elif mode == "crack":
            args = ['svcrack.py', self.crack_target.get(), '-u', self.crack_user.get(), '--numeric', self.crack_pass.get(), '-v']

        self.execute_internal(func, args)

    def execute_internal(self, func, args):
        self.log_area.delete(1.0, tk.END)
        self.is_running = True
        self.status_var.set("内核运行中...")
        self.btn_map_run.config(state="disabled")

        # --- 核心：多流日志拦截引擎 ---
        class UnifiedLogHandler(logging.Handler):
            def __init__(self, widget, master):
                super().__init__()
                self.widget = widget
                self.master = master
            def emit(self, record):
                msg = self.format(record)
                self.master.root.after(0, self._append, msg + '\n')
            def write(self, text): # 兼容 sys.stdout
                if text.strip():
                    self.master.root.after(0, self._append, text)
            def _append(self, text):
                self.widget.insert(tk.END, text)
                self.widget.see(tk.END)
                # 实时提取 IP
                ip_match = re.search(r'\|\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?)', text)
                if ip_match:
                    ip = ip_match.group(1).strip()
                    if ip not in self.master.found_ips:
                        self.master.found_ips.append(ip)
                        self.master.ip_list['values'] = self.master.found_ips
                        self.master.ip_list.set(ip)
            def flush(self): pass

        def run():
            # 1. 备份
            old_stdout = sys.stdout
            old_stderr = sys.stderr
            old_argv = sys.argv
            
            # 2. 创建拦截器
            handler = UnifiedLogHandler(self.log_area, self)
            
            # 3. 拦截 Python logging (sipvicious 核心输出)
            root_logger = logging.getLogger()
            old_level = root_logger.level
            root_logger.setLevel(logging.INFO)
            root_logger.addHandler(handler)
            
            # 4. 拦截系统输出
            sys.stdout = handler
            sys.stderr = handler
            sys.argv = args 
            
            try:
                try:
                    func(args)
                except TypeError:
                    func()
            except Exception as e:
                handler.write(f"\n[!] 内核异常: {e}\n")
            finally:
                # 5. 还原
                root_logger.removeHandler(handler)
                root_logger.setLevel(old_level)
                sys.stdout = old_stdout
                sys.stderr = old_stderr
                sys.argv = old_argv
                self.is_running = False
                self.root.after(0, lambda: self.btn_map_run.config(state="normal"))
                self.root.after(0, lambda: self.status_var.set("任务完成"))

        threading.Thread(target=run, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = SIPViciousFinalBossV4(root)
    root.mainloop()
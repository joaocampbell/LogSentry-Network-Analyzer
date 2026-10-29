"""Optional Tkinter desktop interface for LogSentry. No third-party GUI dependency."""
import json
import os
import queue
import subprocess
import sys
import threading
from datetime import datetime
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path

from . import __version__
from .integrations import discover_integrations

APP_TITLE = f"LogSentry Security Center {__version__}"


class LogSentryGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_TITLE)
        self.geometry("940x720")
        self.minsize(760, 600)
        self.configure(padx=14, pady=12)
        self.queue = queue.Queue()
        self.worker = None
        self.last_html = None
        self.last_json = None
        self.out_dir = tk.StringVar(value=str(Path.home() / "LogSentryReports"))
        self.public_profile = tk.BooleanVar(value=True)
        self.endpoint_audit = tk.BooleanVar(value=True)
        self.discovery_cidr = tk.StringVar()
        self.eve_path = tk.StringVar()
        self.clamav_path = tk.StringVar()
        self._build()
        self._show_integrations()
        try:
            self.after(150, self._poll_queue)
        except tk.TclError:
            # The window may have been closed while a worker was finishing.
            pass

    def _build(self):
        header = ttk.Frame(self)
        header.pack(fill="x", pady=(0, 10))
        ttk.Label(header, text="LogSentry Security Center", font=("TkDefaultFont", 18, "bold")).pack(anchor="w")
        ttk.Label(header, text="Análise de rede e triagem local · modo de leitura por defeito").pack(anchor="w", pady=(3, 0))

        options = ttk.LabelFrame(self, text="Análise", padding=10)
        options.pack(fill="x", pady=(0, 10))
        ttk.Label(options, text="Pasta dos relatórios").grid(row=0, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(options, textvariable=self.out_dir).grid(row=0, column=1, sticky="ew", pady=4)
        ttk.Button(options, text="Escolher…", command=self._choose_output).grid(row=0, column=2, padx=(8, 0), pady=4)
        ttk.Checkbutton(options, text="Perfil público (anonimizar dados sensíveis)", variable=self.public_profile).grid(row=1, column=0, columnspan=3, sticky="w", pady=4)
        ttk.Checkbutton(options, text="Auditar processos e sockets locais", variable=self.endpoint_audit).grid(row=2, column=0, columnspan=3, sticky="w", pady=4)
        ttk.Label(options, text="Rede privada autorizada (opcional, ex. 192.168.1.0/24)").grid(row=3, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(options, textvariable=self.discovery_cidr).grid(row=3, column=1, columnspan=2, sticky="ew", pady=4)
        ttk.Label(options, text="Ficheiro Suricata EVE JSON (opcional)").grid(row=4, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(options, textvariable=self.eve_path).grid(row=4, column=1, sticky="ew", pady=4)
        ttk.Button(options, text="Escolher…", command=self._choose_eve).grid(row=4, column=2, padx=(8, 0), pady=4)
        ttk.Label(options, text="Ficheiro/pasta para ClamAV (opcional)").grid(row=5, column=0, sticky="w", padx=(0, 8), pady=4)
        ttk.Entry(options, textvariable=self.clamav_path).grid(row=5, column=1, sticky="ew", pady=4)
        ttk.Button(options, text="Escolher…", command=self._choose_clamav).grid(row=5, column=2, padx=(8, 0), pady=4)
        options.columnconfigure(1, weight=1)

        actions = ttk.Frame(self)
        actions.pack(fill="x", pady=(0, 10))
        self.run_button = ttk.Button(actions, text="▶  Executar análise", command=self._run_analysis)
        self.run_button.pack(side="left")
        self.refresh_button = ttk.Button(actions, text="Atualizar componentes", command=self._show_integrations)
        self.refresh_button.pack(side="left", padx=(8, 0))
        self.open_html_button = ttk.Button(actions, text="Abrir último relatório HTML", command=self._open_html, state="disabled")
        self.open_html_button.pack(side="right")

        integrations = ttk.LabelFrame(self, text="Componentes detetados automaticamente", padding=8)
        integrations.pack(fill="x", pady=(0, 10))
        integration_body = ttk.Frame(integrations)
        integration_body.pack(fill="x", expand=False)
        self.integration_text = tk.Text(integration_body, height=5, wrap="word", state="disabled", borderwidth=0)
        integration_scroll = ttk.Scrollbar(integration_body, orient="vertical", command=self.integration_text.yview)
        self.integration_text.configure(yscrollcommand=integration_scroll.set)
        self.integration_text.pack(side="left", fill="x", expand=True)
        integration_scroll.pack(side="right", fill="y")

        output_frame = ttk.LabelFrame(self, text="Progresso e resultados", padding=8)
        output_frame.pack(fill="both", expand=True)
        self.progress = ttk.Progressbar(output_frame, mode="indeterminate")
        self.progress.pack(fill="x", pady=(0, 3))
        self.status_var = tk.StringVar(value="Pronto para analisar.")
        ttk.Label(output_frame, textvariable=self.status_var, anchor="w").pack(fill="x", pady=(0, 6))
        output_body = ttk.Frame(output_frame)
        output_body.pack(fill="both", expand=True)
        self.output_text = tk.Text(output_body, wrap="word", state="disabled", height=14)
        output_scroll = ttk.Scrollbar(output_body, orient="vertical", command=self.output_text.yview)
        self.output_text.configure(yscrollcommand=output_scroll.set)
        self.output_text.pack(side="left", fill="both", expand=True)
        output_scroll.pack(side="right", fill="y")
        ttk.Label(self, text="A ausência de alertas não prova ausência de ameaças. Integrações opcionais dependem da respetiva configuração e permissões.", wraplength=900).pack(anchor="w", pady=(8, 0))

    def _choose_output(self):
        chosen = filedialog.askdirectory(title="Escolher pasta para relatórios", initialdir=self.out_dir.get())
        if chosen: self.out_dir.set(chosen)

    def _choose_eve(self):
        chosen = filedialog.askopenfilename(title="Selecionar Suricata EVE JSON", filetypes=[("JSON/logs", "*.json*"), ("Todos os ficheiros", "*.*")])
        if chosen: self.eve_path.set(chosen)

    def _choose_clamav(self):
        chosen = filedialog.askdirectory(title="Escolher pasta para análise ClamAV")
        if not chosen:
            chosen = filedialog.askopenfilename(title="Escolher ficheiro para análise ClamAV")
        if chosen: self.clamav_path.set(chosen)

    def _append(self, text):
        self.output_text.configure(state="normal")
        self.output_text.insert("end", text.rstrip() + "\n")
        self.output_text.see("end")
        self.output_text.configure(state="disabled")

    def _show_integrations(self):
        try:
            info = discover_integrations()
            labels = {
                "nmap": "Nmap", "clamav_scanner": "ClamAV (clamscan)", "clamav_updater": "FreshClam",
                "suricata": "Suricata", "wazuh_agent": "Agente Wazuh", "ss": "ss",
                "iproute2": "iproute2", "ufw": "UFW", "nftables": "nftables",
                "samba_server": "Samba (smbd)", "samba_netbios": "Samba (nmbd)",
                "windows_firewall": "Firewall do Windows", "powershell": "PowerShell",
            }
            lines = [f"{'Disponível' if path else 'Não encontrado':18} · {labels[key]}" + (f" — {path}" if path else "") for key, path in info["binaries"].items()]
            lines.append(f"Ficheiro EVE: {info['suricata_eve_file'] or 'não encontrado nos caminhos padrão'}")
            lines.append(info["note"])
            text = "\n".join(lines)
        except Exception as exc:
            text = f"Não foi possível verificar componentes: {exc}"
        self.integration_text.configure(state="normal")
        self.integration_text.delete("1.0", "end")
        self.integration_text.insert("1.0", text)
        self.integration_text.configure(state="disabled")

    def _run_analysis(self):
        if self.worker and self.worker.is_alive(): return
        out_dir = Path(self.out_dir.get()).expanduser()
        try:
            out_dir.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            messagebox.showerror("Pasta inválida", str(exc)); return
        prefix = out_dir / ("logsentry-report-" + datetime.now().strftime("%Y%m%d-%H%M%S"))
        args = [sys.executable, "-m", "netanalyzer", "--out", str(prefix)]
        if self.public_profile.get(): args += ["--privacy-profile", "public"]
        if self.endpoint_audit.get() or self.clamav_path.get().strip(): args.append("--endpoint-audit")
        cidr = self.discovery_cidr.get().strip()
        if cidr: args += ["--discover-network", cidr]
        eve = self.eve_path.get().strip()
        if eve: args += ["--suricata-eve", eve]
        clam = self.clamav_path.get().strip()
        if clam: args += ["--clamav-scan", clam]
        self.run_button.configure(state="disabled")
        self.refresh_button.configure(state="disabled")
        self.progress.configure(mode="indeterminate", value=0)
        self.progress.start(12)
        self.status_var.set("Análise em execução. Os testes de rede podem demorar alguns segundos…")
        self._append("\nA iniciar análise…")
        self._append("As opções e caminhos pessoais não são repetidos no registo visual.")
        self.worker = threading.Thread(target=self._worker_run, args=(args, str(prefix)), daemon=True)
        self.worker.start()

    def _worker_run(self, args, prefix):
        """Run the CLI outside Tk's event loop and always notify the UI on exit."""
        try:
            proc = subprocess.run(
                args,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=300,
                check=False,
                start_new_session=True,
            )
            self.queue.put(("finished", proc.returncode, proc.stdout, proc.stderr, prefix))
        except subprocess.TimeoutExpired as exc:
            # Preserve any output emitted before the timeout for troubleshooting.
            stdout = exc.stdout or ""
            stderr = exc.stderr or ""
            if isinstance(stdout, bytes): stdout = stdout.decode("utf-8", errors="replace")
            if isinstance(stderr, bytes): stderr = stderr.decode("utf-8", errors="replace")
            detail = "A análise excedeu o limite de 300 segundos e foi interrompida."
            self.queue.put(("error", detail, prefix, stdout, stderr))
        except Exception as exc:
            self.queue.put(("error", f"{type(exc).__name__}: {exc}", prefix, "", ""))

    def _poll_queue(self):
        try:
            while True:
                item = self.queue.get_nowait()
                if item[0] == "finished":
                    _, code, stdout, stderr, prefix = item
                    self.progress.stop()
                    self.progress.configure(value=0)
                    self.run_button.configure(state="normal")
                    self.refresh_button.configure(state="normal")
                    if stdout: self._append(stdout)
                    if stderr: self._append("Avisos/erros:\n" + stderr)
                    json_path = Path(prefix + ".json")
                    html_path = Path(prefix + ".html")
                    if code == 0 and json_path.is_file() and html_path.is_file():
                        self.last_json = str(json_path)
                        self.last_html = str(html_path)
                        self.open_html_button.configure(state="normal")
                        self.status_var.set("Análise concluída. Relatórios HTML e JSON guardados.")
                        self._show_summary(self.last_json)
                    else:
                        self.status_var.set("A análise terminou com erro; consulta os detalhes abaixo.")
                        detail = f"Código de saída: {code}."
                        if not json_path.is_file(): detail += " O relatório JSON não foi encontrado."
                        if not html_path.is_file(): detail += " O relatório HTML não foi encontrado."
                        messagebox.showerror("Análise não concluída", detail + " Consulta os detalhes no painel.")
                elif item[0] == "error":
                    _, detail, prefix, *captured = item
                    self.progress.stop()
                    self.progress.configure(value=0)
                    self.run_button.configure(state="normal")
                    self.refresh_button.configure(state="normal")
                    self.status_var.set("Análise interrompida ou falhada.")
                    self._append("Erro: " + detail)
                    for label, content in zip(("Saída parcial", "Erro parcial"), captured):
                        if content: self._append(f"{label}:\n{content}")
                    messagebox.showerror("Erro de execução", detail)
        except queue.Empty:
            pass
        try:
            self.after(150, self._poll_queue)
        except tk.TclError:
            # The window may have been closed while a worker was finishing.
            pass

    def _show_summary(self, path):
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            checks = data.get("checks", {})
            ok = sum(1 for item in checks.values() if item.get("ok") is True)
            failed = sum(1 for item in checks.values() if item.get("ok") is False)
            self._append("\n=== RESUMO ===")
            self._append(f"Verificações: {ok} OK · {failed} falhadas · {len(checks)} no total")
            endpoint = data.get("endpoint_audit", {})
            if endpoint:
                self._append(f"Processos: {endpoint.get('process_count', 0)} · Sockets em escuta: {endpoint.get('listening_count', 0)} · Candidatos a exposição: {endpoint.get('exposure_finding_count', 0)}")
                clam = endpoint.get("clamav", {})
                self._append(f"ClamAV: {clam.get('status', 'não solicitado')} — {clam.get('message', '')}")
            discovery = data.get("network_discovery")
            if discovery:
                self._append(f"Descoberta de rede: {discovery.get('host_count', 0)} hosts encontrados; {discovery.get('message', '')}")
            threat = data.get("threat_assessment", {})
            suricata = threat.get("suricata", {})
            self._append(f"Suricata: {suricata.get('message', 'sem análise de eventos solicitada')}")
            self._append("Nota: os resultados são triagem; não constituem garantia de ausência de malware.")
        except (OSError, json.JSONDecodeError) as exc:
            self._append(f"Não foi possível ler o resumo JSON: {exc}")

    def _open_html(self):
        if self.last_html and Path(self.last_html).is_file():
            import webbrowser
            webbrowser.open(Path(self.last_html).resolve().as_uri())
        else:
            messagebox.showinfo("Relatório indisponível", "Ainda não existe um relatório HTML nesta sessão.")


def main():
    try:
        app = LogSentryGUI()
        app.mainloop()
        return 0
    except tk.TclError as exc:
        print("Não foi possível iniciar a interface gráfica. Confirma se o Tkinter está instalado e se existe uma sessão gráfica.", file=sys.stderr)
        print(str(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

"""DocRep (RepoMedic) Lightweight Offline GUI Server.

Uses only Python standard library (http.server, threading, webbrowser, socket, json).
Runs exclusively on 127.0.0.1, auto-selects a free port, and opens browser.
"""

from __future__ import annotations

import json
import os
import shutil
import socket
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, List, Optional

from .analyzer import DependencyAnalyzer
from .capsule import CapsuleGenerator
from .hermes_adapter import HermesAdapter
from .impact import ImpactAnalyzer
from .models import FindingStatus
from .scanner import RepositoryScanner
from .verifier import SafeVerificationRunner

STATIC_DIR = Path(__file__).parent / "static"


class JobState:
    IDLE = "idle"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class AnalysisJobManager:
    """Manages background analysis jobs with cancellation and progress reporting."""

    def __init__(self):
        self.lock = threading.Lock()
        self.status = JobState.IDLE
        self.progress_pct = 0
        self.current_step = "Idle"
        self.error_message = ""
        self.cancel_requested = False
        self.last_results: Optional[Dict[str, Any]] = None
        self.last_capsule_md = ""
        self.last_capsule_json = ""
        self.last_reports_dir = ""

    def get_state(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "status": self.status,
                "progress_pct": self.progress_pct,
                "current_step": self.current_step,
                "error_message": self.error_message,
                "has_results": self.last_results is not None,
                "reports_dir": self.last_reports_dir,
            }

    def cancel(self):
        with self.lock:
            if self.status == JobState.RUNNING:
                self.cancel_requested = True
                self.current_step = "Cancelling job..."

    def start_job(
        self,
        repo_path: str,
        action: str = "run",
        deep: bool = False,
        no_ai: bool = False,
        output_dir: str = "reports",
    ) -> bool:
        with self.lock:
            if self.status == JobState.RUNNING:
                return False
            self.status = JobState.RUNNING
            self.progress_pct = 5
            self.current_step = "Validating repository path..."
            self.error_message = ""
            self.cancel_requested = False

        thread = threading.Thread(
            target=self._execute_job,
            args=(repo_path, action, deep, no_ai, output_dir),
            daemon=True,
        )
        thread.start()
        return True

    def _execute_job(
        self,
        repo_path: str,
        action: str,
        deep: bool,
        no_ai: bool,
        output_dir: str,
    ):
        try:
            target_p = Path(repo_path).resolve()
            if not target_p.exists() or not target_p.is_dir():
                raise ValueError(f"Repository path '{repo_path}' does not exist or is not a directory.")

            # Step 1: Scan
            if self._check_cancelled():
                return
            self._update_progress(15, "Step 1/5: Scanning repository files, manifests, and AST imports...")
            scanner = RepositoryScanner(target_p)
            metadata, declarations, imports, m_hashes, s_hashes = scanner.scan()

            if action == "scan":
                self._finish_custom(
                    {
                        "action": "scan",
                        "metadata": metadata.model_dump(),
                        "declarations": [d.model_dump() for d in declarations],
                        "imports": [i.model_dump() for i in imports],
                    }
                )
                return

            # Step 2: Analyze
            if self._check_cancelled():
                return
            self._update_progress(35, "Step 2/5: Evaluating deterministic resilience rules (ghosts, tripwires, conflicts)...")
            analyzer = DependencyAnalyzer(metadata, declarations, imports)
            findings = analyzer.analyze()

            if action == "analyze":
                self._finish_custom(
                    {
                        "action": "analyze",
                        "metadata": metadata.model_dump(),
                        "declarations": [d.model_dump() for d in declarations],
                        "findings": [f.model_dump() for f in findings],
                    }
                )
                return

            # Step 3: Impact
            if self._check_cancelled():
                return
            self._update_progress(55, "Step 3/5: Calculating change blast-radius and affected tests...")
            impact_analyzer = ImpactAnalyzer(declarations, imports)
            blast_radii = impact_analyzer.calculate_blast_radius()

            # Step 4: AI Recommendations & Challenges
            if self._check_cancelled():
                return
            self._update_progress(70, "Step 4/5: Generating AI recommendations and challenges...")
            adapter = HermesAdapter()
            model_info = {
                "model_name": adapter.model_name,
                "endpoint": adapter.endpoint,
                "mode": "no_ai" if no_ai else "local_ollama_hermes",
            }

            if no_ai:
                recommendations = []
            else:
                recommendations = adapter.generate_recommendations(findings)

            # Step 5: Verification
            if self._check_cancelled():
                return
            self._update_progress(85, "Step 5/5: Executing isolated sandbox verification checks...")
            verifier = SafeVerificationRunner(target_p)
            verifications = verifier.run_all_checks()

            if action == "verify":
                self._finish_custom(
                    {
                        "action": "verify",
                        "verifications": [v.model_dump() for v in verifications],
                    }
                )
                return

            # Generate Capsule
            if self._check_cancelled():
                return
            self._update_progress(95, "Finalizing Dependency Exit Capsule (JSON & Markdown)...")
            generator = CapsuleGenerator(
                metadata=metadata,
                declarations=declarations,
                imports=imports,
                findings=findings,
                recommendations=recommendations,
                verifications=verifications,
                blast_radii=blast_radii,
                manifest_hashes=m_hashes,
                source_hashes=s_hashes,
                model_info=model_info,
            )

            out_dir_path = Path(output_dir).resolve()
            json_p = generator.export_json(out_dir_path / "capsule.json")
            md_p = generator.export_markdown(out_dir_path / "capsule.md")

            capsule = generator.build_capsule()
            capsule_dump = capsule.model_dump()

            with self.lock:
                self.last_results = capsule_dump
                self.last_capsule_md = md_p.read_text(encoding="utf-8")
                self.last_capsule_json = json_p.read_text(encoding="utf-8")
                self.last_reports_dir = str(out_dir_path)
                self.progress_pct = 100
                self.current_step = "Analysis complete! Capsule generated."
                self.status = JobState.COMPLETED

        except Exception as e:
            with self.lock:
                self.status = JobState.FAILED
                self.error_message = str(e)
                self.current_step = f"Failed: {e}"

    def _update_progress(self, pct: int, step: str):
        with self.lock:
            self.progress_pct = pct
            self.current_step = step

    def _check_cancelled(self) -> bool:
        with self.lock:
            if self.cancel_requested:
                self.status = JobState.CANCELLED
                self.current_step = "Job cancelled by user."
                return True
            return False

    def _finish_custom(self, data: Dict[str, Any]):
        with self.lock:
            self.last_results = data
            self.progress_pct = 100
            self.current_step = "Operation completed successfully."
            self.status = JobState.COMPLETED


job_manager = AnalysisJobManager()


class DocRepHTTPRequestHandler(BaseHTTPRequestHandler):
    """Custom HTTP Request Handler serving static UI and REST API."""

    def log_message(self, format, *args):
        # Quiet logger for clean CLI output
        pass

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path in ("/", "/index.html"):
            self._serve_static_index()
        elif path == "/api/status":
            self._handle_api_status()
        elif path == "/api/job":
            self._handle_api_job()
        elif path == "/api/results":
            self._handle_api_results()
        elif path == "/api/capsule.md":
            self._handle_download_capsule_md()
        elif path == "/api/capsule.json":
            self._handle_download_capsule_json()
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/run":
            self._handle_api_run()
        elif path == "/api/cancel":
            self._handle_api_cancel()
        else:
            self.send_error(404, "Not Found")

    def _serve_static_index(self):
        index_p = STATIC_DIR / "index.html"
        if not index_p.exists():
            self.send_error(500, "static/index.html not found")
            return
        content = index_p.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)

    def _handle_api_status(self):
        adapter = HermesAdapter()
        runtime = adapter.get_runtime_status()
        warm = adapter.warmup_check()

        ollama_running = warm["status"] == "ok" or (warm.get("error") and "not found in Ollama" in warm["error"])
        model_ready = warm["status"] == "ok"
        models_found = warm.get("models", [])

        status_data = {
            "project_name": "DocRep",
            "version": "0.2.0",
            "hermes": {
                "found": runtime["hermes_cli_found"],
                "path": runtime["hermes_path"],
                "version": runtime["hermes_version"],
                "fix": "Hermes CLI optional; local Ollama endpoint fallback is active." if not runtime["hermes_cli_found"] else None,
            },
            "ollama": {
                "running": ollama_running,
                "endpoint": runtime["local_endpoint"],
                "fix": "Ensure Ollama is running at http://127.0.0.1:11434 (run 'ollama serve' in terminal)" if not ollama_running else None,
            },
            "model": {
                "name": runtime["model_name"],
                "ready": model_ready,
                "models_found": models_found,
                "fix": f"ollama pull {runtime['model_name']}" if not model_ready else None,
            },
            "default_repo": "target_repo/linkwatch",
        }
        self._send_json(status_data)

    def _handle_api_job(self):
        state = job_manager.get_state()
        self._send_json(state)

    def _handle_api_results(self):
        with job_manager.lock:
            res = job_manager.last_results
            md = job_manager.last_capsule_md
            js = job_manager.last_capsule_json
            rdir = job_manager.last_reports_dir

        if not res:
            self._send_json({"error": "No completed analysis results available."}, status=404)
            return

        self._send_json({
            "capsule": res,
            "capsule_md": md,
            "capsule_json": js,
            "reports_dir": rdir,
        })

    def _handle_download_capsule_md(self):
        with job_manager.lock:
            md = job_manager.last_capsule_md
        if not md:
            self.send_error(404, "Capsule Markdown not generated yet.")
            return
        content = md.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/markdown; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="capsule.md"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_download_capsule_json(self):
        with job_manager.lock:
            js = job_manager.last_capsule_json
        if not js:
            self.send_error(404, "Capsule JSON not generated yet.")
            return
        content = js.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", 'attachment; filename="capsule.json"')
        self.send_header("Content-Length", str(len(content)))
        self.end_headers()
        self.wfile.write(content)

    def _handle_api_run(self):
        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length).decode("utf-8")
            data = json.loads(body) if body else {}

            repo_path = data.get("repo_path", "target_repo/linkwatch").strip()
            action = data.get("action", "run")
            deep = bool(data.get("deep", False))
            no_ai = bool(data.get("no_ai", False))
            output_dir = data.get("output_dir", "reports").strip()

            target_p = Path(repo_path).resolve()
            if not target_p.exists() or not target_p.is_dir():
                self._send_json({"error": f"Invalid repository path: Directory '{repo_path}' does not exist."}, status=400)
                return

            started = job_manager.start_job(
                repo_path=str(target_p),
                action=action,
                deep=deep,
                no_ai=no_ai,
                output_dir=output_dir,
            )
            if not started:
                self._send_json({"error": "An analysis job is already currently running."}, status=409)
                return

            self._send_json({"status": "started", "repo_path": str(target_p)})
        except Exception as e:
            self._send_json({"error": f"Bad request: {e}"}, status=400)

    def _handle_api_cancel(self):
        job_manager.cancel()
        self._send_json({"status": "cancelling"})

    def _send_json(self, data: Any, status: int = 200):
        content = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        self.wfile.write(content)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def start_gui_server(repo_path: Optional[str] = None, port: int = 0, no_browser: bool = False):
    """Start the standard-library HTTP server on 127.0.0.1 and optionally launch the browser."""
    actual_port = port if port > 0 else find_free_port()
    server_address = ("127.0.0.1", actual_port)
    server = ThreadingHTTPServer(server_address, DocRepHTTPRequestHandler)
    url = f"http://127.0.0.1:{actual_port}"

    print(f"\n=======================================================")
    print(f"  DocRep (RepoMedic) Workbench Server Online")
    print(f"  URL: {url}")
    print(f"  Binding: 127.0.0.1 only (offline safe, no external calls)")
    print(f"=======================================================\n")

    if not no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nDocRep GUI Server stopped.")
        server.server_close()

# netsage/scanner/plugin_manager.py
import importlib.util
import glob
import os
import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, Any, List

class PluginManager:
    def __init__(self, plugin_folder: str = None, max_workers: int = 10):
        self.plugin_folder = plugin_folder or os.path.join(os.path.dirname(__file__), '../plugins')
        self.plugins: Dict[str, Any] = {}
        self.json_rules: List[Dict[str, Any]] = []
        self.max_workers = max_workers
        self._load_plugins()
        self._load_json_rules()

    def _load_plugins(self):
        for plugin_path in glob.glob(os.path.join(self.plugin_folder, '*.py')):
            module_name = os.path.basename(plugin_path)[:-3]
            if module_name == "__init__":
                continue
            spec = importlib.util.spec_from_file_location(module_name, plugin_path)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)
            self.plugins[module_name] = module

    def _load_json_rules(self):
        for json_path in glob.glob(os.path.join(self.plugin_folder, '*.json')):
            try:
                with open(json_path, 'r', encoding='utf-8') as f:
                    rules = json.load(f)
                    if isinstance(rules, list):
                        self.json_rules.extend(rules)
            except Exception as e:
                print(f"[PluginManager] Failed to load JSON {json_path}: {e}")

    def _apply_json_rules(self, host: str, port: int, banner: str) -> List[Dict[str, Any]]:
        matches = []
        if banner:
            for rule in self.json_rules:
                pattern = rule.get('pattern')
                if pattern and re.search(pattern, banner, re.IGNORECASE):
                    matches.append({
                        "detected": True,
                        "device_type": rule.get("device_type", "Unknown"),
                        "vendor": rule.get("vendor", "Unknown"),
                        "model": rule.get("model", ""),
                        "notes": rule.get("notes", "Matched JSON rule")
                    })
        return matches

    def run_all_plugins(self, host: str, port: int, banner: str) -> List[Dict[str, Any]]:
        """
        Run all Python plugins and JSON rules concurrently for one host/port/banner.
        Returns list of plugin results.
        """
        results = []

        # Function to run a single plugin
        def run_plugin(plugin_name: str, plugin_module: Any):
            try:
                if hasattr(plugin_module, 'run_scan'):
                    result = plugin_module.run_scan(host, port, banner)
                    if result.get('detected'):
                        return result
            except Exception as e:
                return {"detected": False, "device_type": "Error", "vendor": plugin_name, "notes": str(e)}
            return None

        # Run Python plugins concurrently
        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_plugin = {
                executor.submit(run_plugin, name, mod): name for name, mod in self.plugins.items()
            }
            for future in as_completed(future_to_plugin):
                res = future.result()
                if res:
                    results.append(res)

        # Apply JSON rules (can be fast, so sequential is fine)
        results.extend(self._apply_json_rules(host, port, banner))

        return results

    def run_scan_batch(self, scan_targets: Dict[str, List[int]], banners: Dict[str, Dict[int, str]]) -> Dict[str, List[Dict[str, Any]]]:
        """
        Run plugins for a batch of hosts and ports concurrently.
        scan_targets: {host: [port1, port2, ...]}
        banners: {host: {port: banner}}
        Returns dict {host: [plugin_results]}
        """
        final_results = {}

        # Flatten tasks for ThreadPoolExecutor
        tasks = []
        for host, ports in scan_targets.items():
            for port in ports:
                banner = banners.get(host, {}).get(port, "")
                tasks.append((host, port, banner))

        def worker(task):
            host, port, banner = task
            plugin_results = self.run_all_plugins(host, port, banner)
            return host, plugin_results

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = [executor.submit(worker, t) for t in tasks]
            for future in as_completed(futures):
                host, plugin_results = future.result()
                if host not in final_results:
                    final_results[host] = []
                final_results[host].extend(plugin_results)

        return final_results



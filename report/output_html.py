# /report/output_html.py
from jinja2 import Environment, FileSystemLoader
import os
from datetime import datetime

def generate_html_output(results: list, filename: str = 'scan_report.html'):
    """
    Generates a complete, styled HTML report using a Jinja2 template.
    Includes a Chart.js bar chart visualizing port counts per host.
    """
    # 1. Pre-process Data
    grouped_results = {}
    for result in results:
        host = result.get('host')
        if host not in grouped_results:
            grouped_results[host] = []
        grouped_results[host].append(result)

    total_hosts = len(grouped_results)
    total_ports = len(results)

    hosts_list = list(grouped_results.keys())
    ports_count_list = [len(grouped_results[host]) for host in hosts_list]

    # Set up Jinja2 environment
    template_dir = os.path.join(os.path.dirname(__file__), 'templates')
    env = Environment(loader=FileSystemLoader(template_dir))
    template = env.get_template('report.html')

    # Data to pass to the template
    template_data = {
        'scan_results': results,
        'grouped_results': grouped_results,
        'total_hosts': total_hosts,
        'total_ports': total_ports,
        'hosts_list': hosts_list,
        'ports_count_list': ports_count_list,
        'now': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    }

    # 2. Render Template
    try:
        rendered_html = template.render(template_data)

        # 3. Write File
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(rendered_html)

        # 4. Print Message
        print(f"HTML report saved to {filename}")
    except Exception as e:
        print(f"Error generating HTML report: {e}")


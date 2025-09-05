# /report/output_json.py
import json

def generate_json_output(results: list, filename: str = 'scan_results.json'):
    """
    Exports the scan results to a JSON file.
    """
    try:
        with open(filename, 'w') as f:
            json.dump(results, f, indent=4)
        print(f"JSON report saved to {filename}")
    except IOError as e:
        print(f"Error saving JSON report to {filename}: {e}")


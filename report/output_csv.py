# /report/output_csv.py
import csv

def generate_csv_output(results: list, filename: str = 'scan_results.csv'):
    """
    Exports the scan results to a CSV file.
    The CSV file will have headers: host, port, status, banner.
    """
    fieldnames = ['host', 'port', 'status', 'banner']
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()
            for row in results:
                # Ensure all expected fields are present, even if empty
                csv_row = {key: row.get(key, '') for key in fieldnames}
                writer.writerow(csv_row)
        print(f"CSV report saved to {filename}")
    except IOError as e:
        print(f"Error saving CSV report to {filename}: {e}")


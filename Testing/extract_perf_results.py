import os
import re
import csv
import platform

# Detect OS and set default results_dir
if platform.system() == 'Windows':
    results_dir = r'c:\Users\phokamp\Documents\Results'
else:
    results_dir = 'pwd'  # Change as needed

board_map = {
    'vf2': 'VisionFive2',
    'mvj': 'MilkV Jupiter',
    'p550': 'SiFive P550',
    'bgv': 'BeagleV Ahead'
}

metrics = [
    'task-clock',
    'context-switches',
    'cpu-migrations',
    'page-faults',
    'cycles',
    'instructions',
    'branches',
    'branch-misses',
    'seconds time elapsed',
    'seconds user',
    'seconds sys'
]

extra_patterns = [
    (r'cycles\s*#\s*([\d\.]+)\s*GHz', 'cycles_freq'),
    (r'instructions\s*#\s*([\d\.]+)\s*insn per cycle', 'instructions_per_cycle'),
    (r'branches\s*#\s*([\d\.]+)\s*M/sec', 'branches_msec'),
    (r'branch-misses\s*#\s*([\d\.]+)% of all branches', 'branch-misses_percent'),
]

def parse_perf_file(filepath):
    data = {}
    with open(filepath, 'r') as f:
        lines = f.readlines()
        metric_found = False
        for line in lines:
            # General metrics (allow commas in numbers)
            m = re.match(
                r'^\s*([\d\.,]+)\s*(\w+)?\s+([a-zA-Z\-]+)(?:\s*/sec)?\s*(?:#\s*([^\n]+))?$',
                line
            )
            if m:
                metric_found = True
                value = m.group(1).replace(',', '')  # Remove commas for numeric values
                unit = m.group(2)
                metric = m.group(3).strip()
                comment = m.group(4).strip() if m.group(4) else ''
                metric_key = metric
                if metric_key in metrics:
                    if metric_key == 'task-clock' and unit == 'msec':
                        value = str(float(value) / 1000)
                        unit = 'sec'
                    if metric_key.startswith('seconds'):
                        data[metric_key] = value
                    else:
                        data[metric_key] = f"{value} {unit}" if unit and metric_key != 'task-clock' else value
                    if comment:
                        data[metric_key + '_comment'] = comment
            # Time metrics (with comments, allow commas)
            m2 = re.match(
                r'^\s*([\d\.,]+)\s+seconds (time elapsed|user|sys)\s*(?:#\s*([^\n]+))?$',
                line
            )
            if m2:
                metric_found = True
                value = m2.group(1).replace(',', '')
                metric = f"seconds {m2.group(2)}"
                comment = m2.group(3).strip() if m2.group(3) else ''
                if metric in metrics:
                    data[metric] = value
                    if comment:
                        data[metric + '_comment'] = comment
            # Extra metrics (allow commas)
            for pat, key in [
                (r'cycles\s*#\s*([\d\.,]+)\s*GHz', 'cycles_freq'),
                (r'instructions\s*#\s*([\d\.,]+)\s*insn per cycle', 'instructions_per_cycle'),
                (r'branches\s*#\s*([\d\.,]+)\s*M/sec', 'branches_msec'),
                (r'branch-misses\s*#\s*([\d\.,]+)% of all branches', 'branch-misses_percent'),
            ]:
                m = re.search(pat, line)
                if m:
                    metric_found = True
                    data[key] = m.group(1).replace(',', '')
        # If no metrics found, mark as faulty
        if not metric_found:
            data['file_error'] = 'no_metrics_found'
    return data

def get_board_name(filename):
    prefix = filename.split('_')[0].lower()
    return board_map.get(prefix, prefix)

def parse_filename(filename):
    info = {}
    info['multithreaded'] = 'yes' if '_mt' in filename else 'no'
    info['hash_function'] = 'SHA-2' if '_sha2_' in filename else ('SHA-3' if '_sha3_' in filename else '')
    info['implementation'] = 'OpenSSL' if '_ossl_' in filename else ('Internal' if '_int_' in filename else '')
    h_match = re.search(r'_h(\d+)_', filename)
    info['height'] = h_match.group(1) if h_match else ''
    w_match = re.search(r'_w(\d+)_', filename)
    info['winternitz'] = w_match.group(1) if w_match else ''
    if '_gk_' in filename:
        info['operation'] = 'Key generation'
    elif '_sg_' in filename:
        info['operation'] = 'Signing'
    elif '_vf_' in filename:
        info['operation'] = 'Verification'
    else:
        info['operation'] = ''
    return info

# Recursively collect all result files (both *_gk_res_st.txt and *_gk_res_mt.txt)
files = []
for root, _, filenames in os.walk(results_dir):
    for f in filenames:
        if f.endswith('_res_st.txt') or f.endswith('_res_mt.txt'):
            files.append(os.path.join(root, f))

fieldnames = ['board', 'multithreaded', 'hash_function', 'implementation', 'height', 'winternitz', 'operation']
for metric in metrics:
    fieldnames.append(metric)
    fieldnames.append(metric + '_comment')
fieldnames += ['cycles_freq', 'instructions_per_cycle', 'branches_msec', 'branch-misses_percent', 'file_error']

rows = []
for filepath in files:
    filename = os.path.basename(filepath)
    row = {'board': get_board_name(filename)}
    row.update(parse_filename(filename))
    row.update(parse_perf_file(filepath))
    rows.append(row)

csv_path = os.path.join(results_dir, 'perf_results_summary.csv')
with open(csv_path, 'w', newline='') as csvfile:
    writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
    writer.writeheader()
    for row in rows:
        writer.writerow(row)

print(f"Results written to {csv_path}")
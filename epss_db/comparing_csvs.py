import pandas as pd

# Load CSV files
csv1 = pd.read_csv(r'C:\Users\ShivamChopra\Projects\vuln\epss_db\epss_extract.csv')
csv2 = pd.read_csv(r'C:\Users\ShivamChopra\Projects\vulnerabilities\epss_database\epss_DB.csv')

# Merge on 'cve' with an outer join to keep all entries
merged = pd.merge(csv1, csv2, on='cve', how='outer', suffixes=('_file1', '_file2'), indicator=True)

# Find rows where:
# 1. They exist only in one file (_merge != 'both')
# 2. Or, they exist in both but any column is different
diff_rows = []

for idx, row in merged.iterrows():
    if row['_merge'] != 'both':
        diff_rows.append(row)
    else:
        # Compare all columns except 'cve' and '_merge'
        cols_file1 = [col for col in merged.columns if col.endswith('_file1')]
        cols_file2 = [col for col in merged.columns if col.endswith('_file2')]
        for c1, c2 in zip(cols_file1, cols_file2):
            if row[c1] != row[c2]:
                diff_rows.append(row)
                break  # No need to check further columns

# Convert to DataFrame
diff_df = pd.DataFrame(diff_rows)

# Save to CSV log
log_file = r'C:\Users\ShivamChopra\Projects\vuln\epss_db\different_cve_log.csv'
diff_df.to_csv(log_file, index=False)

print(f"Total differing rows: {len(diff_df)}")
print(f"Differences saved to: {log_file}")
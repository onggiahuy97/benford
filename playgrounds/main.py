import pandas as pd

# Check the differences between your files
def analyze_dataset_differences():
    files = ['output1.csv', 'output2.csv', 'output3.csv']
    
    for i, file in enumerate(files, 1):
        try:
            df = pd.read_csv(file)
            
            print(f"=== OUTPUT{i}.CSV ANALYSIS ===")
            print(f"Shape: {df.shape}")
            print(f"Columns: {len(df.columns)}")
            
            # Check if there's a label column
            if 'Label' in df.columns:
                print(f"Label distribution:")
                print(df['Label'].value_counts())
            elif 'Class' in df.columns:
                print(f"Class distribution:")
                print(df['Class'].value_counts())
            
            # Check for malware family indicators in filename
            if 'Filename' in df.columns:
                print(f"Sample filenames:")
                print(df['Filename'].head(3).tolist())
                
                # Extract malware type from filename
                if df['Filename'].str.contains('Spyware', case=False).any():
                    print("Contains: SPYWARE samples")
                if df['Filename'].str.contains('Ransomware', case=False).any():
                    print("Contains: RANSOMWARE samples")  
                if df['Filename'].str.contains('Trojan', case=False).any():
                    print("Contains: TROJAN samples")
                if df['Filename'].str.contains('Benign', case=False).any():
                    print("Contains: BENIGN samples")
            
            # Check data statistics
            print(f"Memory statistics (first numeric column):")
            numeric_cols = df.select_dtypes(include=[np.number]).columns
            if len(numeric_cols) > 0:
                first_col = numeric_cols[0]
                print(f"  {first_col} - Mean: {df[first_col].mean():.2f}, Std: {df[first_col].std():.2f}")
            
            print("-" * 50)
            
        except Exception as e:
            print(f"Error reading {file}: {e}")

# Run the analysis
analyze_dataset_differences()
# Benford's Law Analysis - Python Implementation

This repository contains Python implementations of MATLAB scripts for analyzing data using Benford's law for malware detection research.

## Converted Files

The following MATLAB files have been converted to Python:

1. **Z.m** → **z_test.py** - Z-test statistical analysis
2. **Mad_Pearson.m** → **mad_pearson.py** - MAD and Pearson correlation analysis
3. **KullbackLeibler.m** → **kullback_leibler.py** - Kullback-Leibler divergence analysis
4. **Kolmogorov.m** → **kolmogorov.py** - Kolmogorov-Smirnov test analysis
5. **JensenShannon.m** → **jensen_shannon.py** - Jensen-Shannon divergence analysis

## Installation

1. Install required dependencies:
```bash
pip install -r requirements.txt
```

## Usage

Before running any script, update the `filename` variable in each Python file to point to your Excel data file.

### Running Individual Tests

```bash
# Z-test analysis
python z_test.py

# MAD and Pearson correlation analysis
python mad_pearson.py

# Kullback-Leibler divergence analysis
python kullback_leibler.py

# Kolmogorov-Smirnov test analysis
python kolmogorov.py

# Jensen-Shannon divergence analysis
python jensen_shannon.py
```

## Input Data Format

The scripts expect Excel files (.xlsx) with data starting from row 2, column 1. The data should contain numeric values for first digit analysis.

## Output Files

Each script generates specific output files:

- **z_test.py**: `flow_Z_labels_Benford.txt`
- **mad_pearson.py**: `flow_MAD_labels_Benford.txt`, `flow_Pearson_labels_Benford*.txt`
- **kullback_leibler.py**: `kl_pvalues.txt`, `flow_KL_labels_Benford005.txt`
- **kolmogorov.py**: `ks_pvalues.txt`, `flow_KS_labels_Benford*.txt`
- **jensen_shannon.py**: `jensen_labels.txt`

## Key Features

- **Statistical Tests**: Implements various statistical tests to compare data distributions against Benford's law
- **Visualization**: Generates plots comparing observed frequencies with Benford's law expectations
- **Monte Carlo Simulation**: Kullback-Leibler analysis includes extensive Monte Carlo simulation
- **Multiple Thresholds**: Several scripts test different p-value thresholds for classification

## Notes

- All scripts include error handling for missing files
- File paths are configurable at the top of each script
- The implementations maintain the statistical rigor of the original MATLAB code
- Visualization is provided where appropriate using matplotlib

## Dependencies

- numpy: Numerical computing
- pandas: Data manipulation and Excel file reading
- matplotlib: Plotting and visualization
- scipy: Statistical functions
- openpyxl: Excel file support
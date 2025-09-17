import numpy as np
import pandas as pd
from scipy.stats import norm
import warnings
warnings.filterwarnings('ignore')

def main():
    print("Z-test implementation for Benford's law analysis")
    print("=" * 80)

    # File path - update this to match your data location
    filename = 'Merged_malicious.xlsx'

    try:
        # Read Excel file starting from row 2, column 1
        df = pd.read_excel(filename, header=None)
        vnc = df.iloc[1:, 0].values  # Skip first row, take first column

        # Calculate first digit
        calculate_first_digit = np.array([int(str(v)[0]) for v in vnc if str(v)[0].isdigit()])

        nlines, ncolumns = calculate_first_digit.shape[0], 1
        print(f"Data dimensions: {nlines} lines, {ncolumns} columns")

        # Count occurrences of each digit (1-9)
        digits = np.arange(1, 10)
        counts = np.histogram(calculate_first_digit, bins=np.append(digits, 10))[0]

        print("Counting of the first digits in each row [Cell]:")
        print("+" * 80)

        # Calculate frequencies
        sum1 = np.sum(counts)
        freq_occurrence = counts / sum1
        freq_occurrence1 = freq_occurrence.reshape(1, -1)  # Make it 2D for consistency

        # Benford's law
        benford = np.log10(1 + (1 / digits))
        ben = benford

        print("Mathematical tests performance:")
        print("-" * 80)

        # Z-test implementation
        N_observations = np.sum(freq_occurrence1, axis=1)
        Z_values = np.zeros_like(freq_occurrence1)

        # Calculate Z-test for each row of observed frequencies
        for i in range(freq_occurrence1.shape[0]):
            for j in range(len(ben)):
                O_i = freq_occurrence1[i, j]  # Observed frequency for digit j
                E_i = ben[j]                  # Expected frequency for digit j
                N = N_observations[i]         # Total observations in row i

                # Z-test formula
                Z_values[i, j] = abs(O_i - E_i) * (1/(2*N)) / np.sqrt(E_i * (1 - E_i) / N)

        abs_Z_sum = np.sum(np.abs(Z_values), axis=1)
        p_values_global = 2 * (1 - norm.cdf(abs_Z_sum / np.sqrt(9)))

        # Calculate confidence bounds
        upper_bound = benford + (1.96 * np.sqrt((benford * (1 - benford)) / nlines)) + (1/(2*nlines))
        lower_bound = benford - (1.96 * np.sqrt((benford * (1 - benford)) / nlines)) - (1/(2*nlines))

        # Percentile thresholds
        percentile_lower = 85
        percentile_upper = 95

        # Calculate thresholds based on percentiles
        threshold_lower = np.percentile(p_values_global, percentile_lower)
        threshold_upper = np.percentile(p_values_global, percentile_upper)

        print(f'Lower threshold (percentile {percentile_lower}): {threshold_lower:.4f}')
        print(f'Upper threshold (percentile {percentile_upper}): {threshold_upper:.4f}')

        # Generate results for comparison with labels
        print("Results for comparison with labels-Benford using Z:")
        print("Labels L.. wait")

        with open("flow_Z_labels_Benford.txt", "w") as f:
            for l in range(len(p_values_global)):
                if (p_values_global[l] <= threshold_lower or
                    p_values_global[l] >= threshold_upper):
                    f.write(f'{l+1},1.0\n')
                else:
                    f.write(f'{l+1},0.0\n')

        print("Z-test analysis completed successfully!")
        print(f"Results saved to: flow_Z_labels_Benford.txt")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        print("Please update the filename variable with the correct path to your data file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
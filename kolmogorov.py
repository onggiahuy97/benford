import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import ks_2samp
import warnings
warnings.filterwarnings('ignore')

def main():
    print("Kolmogorov-Smirnov test analysis for Benford's law")
    print("=" * 80)

    # File path - update this to match your data location
    filename = 'Merged_malicious.xlsx'

    try:
        # Read Excel file starting from row 2, column 1
        df = pd.read_excel(filename, header=None)
        vnc = df.iloc[1:, 0].values  # Skip first row, take first column

        # Calculate first digit
        calculate_first_digit = np.array([int(str(v)[0]) for v in vnc if str(v)[0].isdigit()])

        nlines = len(calculate_first_digit)
        print(f"Processing {nlines} data points")

        # Count occurrences of each digit (1-9)
        digits = np.arange(1, 10)
        counts = np.histogram(calculate_first_digit, bins=np.append(digits, 10))[0]

        print("Counting of the first digits in each row [Cell]:")
        print("+" * 80)

        # Calculate frequencies
        sum1 = np.sum(counts)
        freq_occurrence = counts / sum1
        freq_occurrence1 = freq_occurrence.reshape(1, -1)

        print("+" * 80)
        print('Total count of the first digits in the dataset')

        count = np.histogram(calculate_first_digit, bins=np.append(digits, 10))[0]
        sum2 = np.sum(count)
        relative_frequency = count / sum2

        # Benford's law
        benford = np.log10(1 + (1 / digits))

        # Create plot
        plt.figure(1, figsize=(10, 6))
        x = np.arange(1, 10)
        plt.plot(x, benford, 'r-', label='Benford', linewidth=2)
        plt.plot(x, relative_frequency, 'b-', label='Relative frequency of each digit', linewidth=2)
        plt.title("Benford's law")
        plt.xlabel('Digits')
        plt.ylabel('Frequencies of each digit')
        plt.legend()
        plt.grid(True)
        plt.show()

        # Pearson correlation for the total of flows
        correlation_matrix = np.corrcoef(relative_frequency, benford)
        corre_benford_total = correlation_matrix[0, 1]

        # For p-value calculation (simplified)
        from scipy.stats import pearsonr
        _, pvalue1_benford_total = pearsonr(relative_frequency, benford)

        print(f"Total correlation: {corre_benford_total:.4f}, p-value: {pvalue1_benford_total:.4f}")

        # Pearson correlation using Benford law for each flow
        corre_benford, pvalue1_benford = pearsonr(freq_occurrence, benford)
        print(f"Flow correlation: {corre_benford:.4f}, p-value: {pvalue1_benford:.4f}")

        # Kolmogorov-Smirnov test
        print("Performing Kolmogorov-Smirnov test...")

        # Initialize vector to store p-values
        num_columns = freq_occurrence1.shape[1]
        p_valores = np.zeros(1)  # Single sample case

        # Calculate p-value using scipy's ks_2samp
        # For single distribution comparison
        _, p_valor = ks_2samp(freq_occurrence, benford)
        p_valores[0] = p_valor

        # Save KS p-values
        with open("ks_pvalues.txt", "w") as f:
            for p_val in p_valores:
                f.write(f'{p_val}\n')

        # Kolmogorov-Smirnov test implementation
        print("Results for comparison with labels-Benford using KS:")
        print("Labels KS:")

        # Calculate cumulative distributions
        absolute_frequency = np.cumsum(freq_occurrence) / np.sum(freq_occurrence)
        absolute_frequency_benford = np.cumsum(benford) / np.sum(benford)

        # Calculate differences
        difference1 = np.abs(absolute_frequency - absolute_frequency_benford)
        difference2 = np.abs(absolute_frequency_benford[1:] - absolute_frequency[:-1])

        D = np.max(difference1)
        D1 = np.max(difference2) if len(difference2) > 0 else 0
        Z = np.sqrt(sum1) * max(D, D1)

        # Calculate p-value based on Z statistic
        if Z >= 0 and Z < 0.27:
            p = 1
        elif Z >= 0.27 and Z < 1:
            Q = np.exp((-1.233701) * Z**(-2))
            p = 1 - (2.506628 / Z) * (Q + Q**9 + Q**25)
        elif Z >= 1 and Z < 3.1:
            Q = np.exp(-2 * Z**2)
            p = Q - Q**4 + Q**9 - Q**16
        elif Z >= 3.1:
            p = 0

        # Find the point of greatest difference
        max_idx = np.argmax(np.abs(difference1))
        max_diff_x = max_idx + 1  # +1 because digits start from 1
        max_diff_y_observed = absolute_frequency[max_idx]
        max_diff_y_theoretical = absolute_frequency_benford[max_idx]

        f_diff = np.abs(difference1[max_idx])

        # Create KS test visualization
        plt.figure(figsize=(10, 6))
        plt.plot(x, absolute_frequency, '-+k', linewidth=1.5, label='Observed Frequency')
        plt.plot(x, absolute_frequency_benford, '--k', linewidth=1.5, label='Benford Law')

        # Highlight the biggest difference
        plt.plot([max_diff_x, max_diff_x],
                [max_diff_y_observed, max_diff_y_theoretical],
                'k--', linewidth=1.5)
        plt.scatter(max_diff_x, max_diff_y_observed, s=100, c='k', marker='o')
        plt.scatter(max_diff_x, max_diff_y_theoretical, s=100, c='k', marker='o')

        plt.legend(loc='best')
        plt.xlabel('First digit')
        plt.ylabel('Frequency of occurrence')
        plt.title(f'Kolmogorov-Smirnov test: D = {D:.4f}')
        plt.grid(True)
        plt.show()

        print("Results for comparison with labels-Benford using KS:")

        # Generate output files with different p-value thresholds
        with open("flow_KS_labels_Benford005.txt", "w") as f:
            if p_valores[0] < 0.05:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        with open("flow_KS_labels_Benford01.txt", "w") as f:
            if p_valores[0] < 0.1:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        with open("flow_KS_labels_Benford001.txt", "w") as f:
            if p_valores[0] < 0.01:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        print("Kolmogorov-Smirnov analysis completed successfully!")
        print("Output files generated:")
        print("- ks_pvalues.txt")
        print("- flow_KS_labels_Benford005.txt")
        print("- flow_KS_labels_Benford01.txt")
        print("- flow_KS_labels_Benford001.txt")
        print(f"KS statistic D: {D:.6f}")
        print(f"P-value: {p_valores[0]:.6f}")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        print("Please update the filename variable with the correct path to your data file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
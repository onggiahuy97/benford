import numpy as np
import pandas as pd
import warnings
warnings.filterwarnings('ignore')

def main():
    print("Kullback-Leibler divergence analysis for Benford's law")
    print("=" * 80)

    # File path - update this to match your data location
    filename = 'Merged1mal.xlsx'

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

        # Benford's law
        benford = np.log10(1 + (1 / digits))
        ben = benford

        # Monte-Carlo simulation
        adjusted_freq = freq_occurrence1 + (freq_occurrence1 == 0) * 1e-10
        observed_frequency = adjusted_freq

        print("Starting Monte-Carlo simulation...")

        # Part one: number of simulations
        simulations = 1000000
        number_digits = len(ben)
        simulated_KLS = np.zeros(simulations)

        # Part two: generate the simulated data based on Benford's law
        # calculate the divergence of KL
        print(f"Running {simulations} simulations...")
        for i in range(simulations):
            if i % 100000 == 0:
                print(f"Simulation {i}/{simulations}")

            simulated_data = np.random.rand(number_digits)
            simulated_data = simulated_data / np.sum(simulated_data)
            simulated_KL = np.sum(simulated_data * np.log(simulated_data / ben))
            simulated_KLS[i] = simulated_KL

        print("Simulation completed. Calculating KL divergences...")

        # Kullback-Leibler divergence calculation
        # Note: For single sample, we'll treat it as multiple rows for consistency
        kl_divergences = np.zeros(1)
        p_values = np.zeros(1)

        # Calculate KL divergence
        kl_div = np.sum(adjusted_freq[0, :] * np.log(adjusted_freq[0, :] / ben))
        kl_divergences[0] = kl_div

        # Calculate p-value
        p_values[0] = np.mean(simulated_KLS >= kl_div)

        # Percentile calculation
        percentile_lower = 80
        percentile_upper = 90

        # Calculate thresholds based on percentiles
        threshold_lower = np.percentile(p_values, percentile_lower)
        threshold_upper = np.percentile(p_values, percentile_upper)

        print(f'Lower threshold (percentile {percentile_lower}): {threshold_lower:.4f}')
        print(f'Upper threshold (percentile {percentile_upper}): {threshold_upper:.4f}')

        # Save p-values
        with open("kl_pvalues.txt", "w") as f:
            for p_val in p_values:
                f.write(f'{p_val}\n')

        print("Results for comparison with labels-Benford using KL:")

        # Generate labels based on thresholds
        with open("flow_KL_labels_Benford005.txt", "w") as f:
            for l, p_val in enumerate(p_values):
                if p_val <= threshold_lower or p_val >= threshold_upper:
                    f.write(f'{l+1},1.0\n')
                else:
                    f.write(f'{l+1},0.0\n')

        print("Kullback-Leibler analysis completed successfully!")
        print("Output files generated:")
        print("- kl_pvalues.txt")
        print("- flow_KL_labels_Benford005.txt")
        print(f"KL divergence: {kl_div:.6f}")
        print(f"P-value: {p_values[0]:.6f}")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        print("Please update the filename variable with the correct path to your data file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
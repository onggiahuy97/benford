import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
from scipy.stats import pearsonr
import warnings
warnings.filterwarnings('ignore')

def main():
    print("MAD and Pearson correlation analysis for Benford's law")
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
        print(f"Data size: {nlines} samples")

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
        plt.plot(x, benford, '--', label='Benford', color='red')
        plt.plot(x, relative_frequency, 'k-', label='Relative frequency of each digit')
        plt.title("Benford's law")
        plt.xlabel('Digits')
        plt.ylabel('Frequencies of each digit')
        plt.legend()
        plt.grid(True)
        plt.show()

        # Pearson correlation for the total of flows
        corre_benford_total, pvalue1_benford_total = pearsonr(relative_frequency, benford)
        print(f"Total correlation: {corre_benford_total:.4f}, p-value: {pvalue1_benford_total:.4f}")

        # Pearson correlation using Benford law for each flow
        corre_benford, pvalue1_benford = pearsonr(freq_occurrence, benford)
        print(f"Flow correlation: {corre_benford:.4f}, p-value: {pvalue1_benford:.4f}")

        # MAD (Mean Absolute Deviation) calculation
        mad = np.abs(freq_occurrence - benford)
        soma1 = np.sum(mad)
        soma = soma1 / 9

        desvio_padrao_mediana = np.std(mad)
        limite_inferior = soma - desvio_padrao_mediana
        limite_superior = soma + desvio_padrao_mediana
        diferenca = (limite_superior + limite_inferior) / 2
        limite2 = limite_inferior + diferenca

        media_limite2 = np.mean(limite2)
        desvio_padrao_limite2 = np.std(limite2)
        limite_inferior_ajustado = round(media_limite2 - desvio_padrao_limite2, 2)
        limite_superior_ajustado = round(media_limite2 + desvio_padrao_limite2, 2)

        print("Results for comparison with labels-Benford using MAD:")

        with open("flow_MAD_labels_Benford.txt", "w") as f:
            for l in range(1):  # Only one sample in this case
                if soma <= 0.06:
                    f.write(f'{l+1},0.0\n')
                elif 0.06 < soma <= 0.12:
                    f.write(f'{l+1},1.0\n')
                elif soma > 0.12:
                    f.write(f'{l+1},1.0\n')

        print("Results for comparison with labels-Benford using Pearson:")
        print("Labels Pearson.. wait")

        # Pearson test with p-value 0.05
        with open("flow_Pearson_labels_Benford5.txt", "w") as f:
            if pvalue1_benford < 0.05:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        # Pearson test with p-value 0.1
        with open("flow_Pearson_labels_Benford01.txt", "w") as f:
            if pvalue1_benford < 0.1:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        # Pearson test with p-value 0.01
        with open("flow_Pearson_labels_Benford001.txt", "w") as f:
            if pvalue1_benford < 0.01:
                f.write('1,1.0\n')
            else:
                f.write('1,0.0\n')

        print("MAD and Pearson analysis completed successfully!")
        print("Output files generated:")
        print("- flow_MAD_labels_Benford.txt")
        print("- flow_Pearson_labels_Benford5.txt")
        print("- flow_Pearson_labels_Benford01.txt")
        print("- flow_Pearson_labels_Benford001.txt")

    except FileNotFoundError:
        print(f"Error: File '{filename}' not found.")
        print("Please update the filename variable with the correct path to your data file.")
    except Exception as e:
        print(f"An error occurred: {str(e)}")

if __name__ == "__main__":
    main()
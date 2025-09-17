clc;
close all;
clear;
workspace;
fontSize = 10;

filename = ('C:\Users\pedro\OneDrive - TUS MM\Novo Artigo 3\iov2\malicious\Merged_malicious.xlsx');
vnc = readcell(filename,'Range',[2 1]);
calculate_first_digit=cellfun(@(v)v(1),""+vnc)-'0';
    
[nlines,ncolumns] = size(calculate_first_digit);
c = unique(calculate_first_digit);
fprintf('Counting of the first digits in each row [Cell]:\n');
%counts=histc(calculate_first_digit',1:max(calculate_first_digit(:))).';
counts=histc(calculate_first_digit',1:9).';
disp("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
digits = (1:9).';
conta1 = histcounts(calculate_first_digit,[digits;inf]);

fprintf("Sum of the number elements of each row:\n");
sum1 = sum(counts,2)
fprintf("Calculates the relative frequency of each row\n");
freq_occurance = (counts ./sum1).' %sum1
freq_occurance1= (counts ./sum1)    %sum1

disp("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
fprintf('Total count of the first digits in the dataset\n');
count = histcounts(calculate_first_digit,[digits;inf]);
sum2 = sum(count,"all")
relative_frequency = (count ./ sum2).'; %(nlines * ncolumns)

% Benford law:
benford = log10(1+(1./(digits)));
figure(1)
x = 1:9;
plot(x,benford,'r',x,relative_frequency,'b')
title("Benford's law")
xlabel('Digits')
ylabel('Frequencies of each digit')
legend('Benford','Relative frequency of each digit')

% Pearson correlation for the total of flows:
[corre_benford_total,pvalue1_benford_total] = corr(relative_frequency,benford)

%Pearson correlation using Benford law for each flow: *************************************************
[corre_benford, pvalue1_benford] = corr(freq_occurance,benford)
% 
% Komolgorov-smirnov test
% 
% Inicializar vetor para armazenar os p-valores
num_colunas = size(freq_occurance, 2);
p_valores = zeros(num_colunas, 1);

% Calcular o p-valor coluna a coluna
for coluna = 1:num_colunas
    % Selecionar a coluna correspondente da primeira matriz
    coluna_primeira_matriz = freq_occurance(:, coluna);

    % Calcular o p-valor entre a coluna da primeira matriz e a segunda matriz
    [~,p_valor] = kstest2(coluna_primeira_matriz, benford);
    p_valores(coluna) = p_valor;
end

fks_pValues = fopen("ks_pvalues.txt","w");
 for l=1:nlines
   for y=1:1 
         fprintf(fks_pValues,'%d\n',p_valores(l,y));
    end
 end
fclose(fks_pValues);

%Komolgorov - Smirnov test ********************************************
fprintf("Results for comparison with labels-Benford using KS:\n");
fprintf("Labels KS:\n");
Absolute_frequency = cumsum(freq_occurance(1:9,14))./sum(freq_occurance(1:9,14));
Absolute_frequency_Benford = cumsum(benford)./sum(benford);
Difference1 = abs(Absolute_frequency - Absolute_frequency_Benford);
Difference2 = abs(Absolute_frequency_Benford(2:end,:) - Absolute_frequency(1:end-1,:));
D = max(Difference1).';
D1 = max(Difference2).';
Z =sqrt(sum1).*max(D,D1);

% % Inicializar vetor de p-valores
p = zeros(size(Z, 1), 1);

% Calcular p para cada linha de Z
for i = 1:size(Z, 1)
    if any(Z(i) >= 0) && any(Z(i) < 0.27)
        p(i) = 1;
    elseif any(Z(i) >= 0.27) && any(Z(i) < 1)
        Q = exp((-1.233701) * Z(i)^(-2));
        p(i) = 1 - (2.506628 / Z(i)) * (Q + Q^9 + Q^25);
    elseif any(Z(i) >= 1) && any(Z(i) < 3.1)
        Q = exp(-2 * Z(i)^2);
        p(i) = Q - Q^4 + Q^9 - Q^16;
    elseif Z(i) >= 3.1
        p(i) = 0;
    end
end
% 

% Finding the point of greatest difference
[~, maxIdx] = max(abs(Difference1));
max_diff_x = maxIdx;
max_diff_y_observed = Absolute_frequency(maxIdx);
max_diff_y_theoretical =Absolute_frequency_Benford(maxIdx);

f = abs(Difference1(maxIdx));
figure;
hold on;

plot(x, Absolute_frequency, '-+k', 'LineWidth', 1.5);

plot(x, Absolute_frequency_Benford, '--k', 'LineWidth', 1.5);

% Highlight the biggest difference
plot([max_diff_x, max_diff_x], [max_diff_y_observed, max_diff_y_theoretical], 'k--', 'LineWidth', 1.5);
scatter(max_diff_x, max_diff_y_observed, 100, 'k', 'filled');
scatter(max_diff_x, max_diff_y_theoretical, 100, 'k', 'filled');


legend('Observed Frequency', 'Benford Law', 'Location', 'Best');
xlabel('First digit');
ylabel('Frequency of occurrence');
title(['Kolmogorov-Smirnov test: D = ', num2str(D)]);
grid on;
hold off;

% 
fprintf("Results for comparison with labels-Benford using KS:\n");

fKS_first_benford = fopen("flow_KS_labels_Benford005.txt","w");
 for l=1:nlines
   for y=1:1 
     if(p_valores(l,y) <0.05) %
         fprintf(fKS_first_benford,'%d,1.0\n',l); 
     else 
             fprintf(fKS_first_benford,'%d,0.0\n',l);
     end
    end
 end
fclose(fKS_first_benford);



fKS_second_benford = fopen("flow_KS_labels_Benford01.txt","w");
 for l=1:nlines
   for y=1:1 
     if(p_valores(l,y) < 0.1) %pvalue1_benford
         fprintf(fKS_second_benford,'%d,1.0\n',l); % 0 - malicious I need to change
         else
         fprintf(fKS_second_benford,'%d,0.0\n',l); % 1 - normal I need to change for future
     end
    end
 end
fclose(fKS_second_benford);


fKS_third_benford = fopen("flow_KS_labels_Benford001.txt","w");
 for l=1:nlines
   for y=1:1 
     if(p_valores(l,y) < 0.01) %pvalue1_benford
         fprintf(fKS_third_benford,'%d,1.0\n',l); 
         else
         fprintf(fKS_third_benford,'%d,0.0\n',l); 
     end
    end
 end
fclose(fKS_third_benford);






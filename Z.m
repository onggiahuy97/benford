clc;
close all;
clear;
workspace;
fontSize = 10;

%Preprocessing phase %
%+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
filename = ('C:\Users\pedro\OneDrive - TUS MM\Novo Artigo 3\iov2\malicious\Merged_malicious.xlsx');  
vnc = readcell(filename,'Range',[2 1]);
calculate_first_digit=cellfun(@(v)v(1),""+vnc)-'0';
[nlines,ncolumns] = size(calculate_first_digit);
c = unique(calculate_first_digit);
fprintf('Counting of the first digits in each row [Cell]:\n');
%counts=histc(calculate_first_digit',1:max(calculate_first_digit(:))).';
counts=histc(calculate_first_digit.',1:9).';
disp("++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++")
digits = (1:9).';
conta1 = histcounts(calculate_first_digit,[digits;inf]);

fprintf("Sum of the number elements of each row:\n");
sum1 = sum(counts,2)
fprintf("Calculates the relative frequency of each row\n");
freq_occurance = (counts ./sum1).' %sum1
freq_occurance1= (counts ./sum1)    %sum1

% Benford law:
benford = log10(1+(1./(digits)));
ben = benford.';
% +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++


% Mathematical tests performance:
% ------------------------------------------------------------------------------------------------------------

% 1. Pearson correlation using Benford law for each flow: *************************************************
%[corre_benford, pvalue1_benford] = corr(freq_occurance,benford)

% 2. Z_test
N_observacoes = sum(freq_occurance1, 2);
Z_values = zeros(size(freq_occurance1));
% Cálculo do Z-test para cada linha de frequências observadas
for i = 1:size(freq_occurance1, 1)
    for j = 1:length(ben)
        O_i = freq_occurance1(i, j);  % Frequência observada para o dígito j
        E_i = ben(j);        % Frequência esperada para o dígito j
        N = N_observacoes(i);                % Número total de observações na linha i
       
        % Z-test formula
        Z_values(i, j) = abs(O_i - E_i) * (1/2*N) / sqrt(E_i * (1 - E_i) / N);
 
    end
end
abs_Z_sum = sum(abs(Z_values), 2);
p_values_global =2* (1 - normcdf(abs_Z_sum / sqrt(9)));

upper_bound = benford + (1.96 * sqrt((benford .* (1 - benford)) ./ nlines)) + (1/(2*nlines))
lower_bound = benford - (1.96 * sqrt((benford .* (1 - benford)) ./ nlines)) - (1/(2*nlines))


%pval_benignos = p_values_global(1:29298);   % Primeiros 29298 fluxos são benignos
%pval_maliciosos = p_values_global(29299:end);  % Restantes 29298 são maliciosos

percentil_inferior = 85;
percentil_superior = 95;

% Calcular os limites com base nos percentis 
limiar_inferior = prctile(p_values_global, percentil_inferior);
limiar_superior = prctile(p_values_global, percentil_superior);

% Exibir os limites calculados
fprintf('Limiar inferior (percentil %d): %.4f\n', percentil_inferior, limiar_inferior);
fprintf('Limiar superior (percentil %d): %.4f\n', percentil_superior, limiar_superior);


fprintf("Results for comparison with labels-Benford using Z:\n");
fprintf("Labels L.. wait\n");
fZ_first_benford = fopen("flow_Z_labels_Benford.txt","w");
 for l=1:nlines
   for y=1:1 
     if(p_values_global(l,y) <= limiar_inferior || p_values_global(l,y) >= limiar_superior) %
         fprintf(fZ_first_benford,'%d,1.0\n',l); 
     else 
             fprintf(fZ_first_benford,'%d,0.0\n',l);
     end
    end
 end
fclose(fZ_first_benford);
% 

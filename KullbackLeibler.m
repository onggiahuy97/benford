clc;
close all;
clear;
workspace;
fontSize = 10;

filename = ('C:\Users\pedro\OneDrive - TUS MM\Novo Artigo 3\iov2\malicious\Merged1mal.xlsx');
%t = readtable(filename);
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

 % Monte-Carlo simulation
    adjusted_freq = freq_occurance1 + (freq_occurance1 == 0) * 1e-10;
    Observed_frequency = adjusted_freq;

 % Part one: number of simulations
    simulations = 1000000;
    number_digits = length(ben);
    simulated_KLS = zeros(simulations,1);

 % Part two: generate the simulated data basead on the benford law
 % calculate the divergence of KL.
 for i=1:simulations
    simulated_data = rand(1, number_digits);
    simulated_data = simulated_data / sum(simulated_data); 
    simulated_KL = sum(simulated_data .* log(simulated_data ./ ben));
    simulated_KLS(i) = simulated_KL;
 end 

% % 3. Divergência de Kullback-Leibler
kl_divergences = zeros(254311, 1);
p_values = zeros(254311, 1);
 for i = 1:nlines
  %adjusted_freq = freq_occurance1 + (freq_occurance1 == 0) * 1e-10;
  %Calcular a divergência de Kullback-Leibler
  kl_div = sum(adjusted_freq(i,:) .* log(adjusted_freq(i,:) ./ ben));
  % kl_div = sum(freq_occurance1(i,:) .* log(freq_occurance1(i,:) ./ (benford * sum(freq_occurance1(i,:)))));
  kl_divergences(i) = kl_div;
  % p-value
  p_values(i) = mean(simulated_KLS >= kl_div);
 end

%pval_benignos = p_values(1:29298);   % Primeiros 29298 fluxos são benignos
%pval_maliciosos = p_values(29299:end);  % Restantes 29298 são maliciosos

percentil_inferior = 80;
percentil_superior = 90;

% Calcular os limites com base nos percentis dos p-valores benignos
limiar_inferior = prctile(p_values, percentil_inferior); %pval_benignos
limiar_superior = prctile(p_values, percentil_superior);

% Exibir os limites calculados
fprintf('Limiar inferior (percentil %d): %.4f\n', percentil_inferior, limiar_inferior);
fprintf('Limiar superior (percentil %d): %.4f\n', percentil_superior, limiar_superior);


fKL_pValues = fopen("kl_pvalues.txt","w");
 for l=1:nlines
   for y=1:1 
         fprintf(fKL_pValues,'%d\n',p_values(l,y));
    end
 end
fclose(fKL_pValues);

fprintf("Results for comparison with labels-Benford using KL:\n");

fKL_first_benford = fopen("flow_KL_labels_Benford005.txt","w");
 for l=1:nlines
   for y=1:1 
     if(p_values(l,y) <= limiar_inferior || p_values(l,y) >= limiar_superior) %
         fprintf(fKL_first_benford,'%d,1.0\n',l); 
     else 
             fprintf(fKL_first_benford,'%d,0.0\n',l);
     end
    end
 end
fclose(fKL_first_benford);


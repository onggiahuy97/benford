clc;
close all;
clear;
workspace;
fontSize = 10;

filename = ('C:\Users\pedro\OneDrive - TUS MM\Novo Artigo 3\iov2\malicious\Merged1mal.xlsx');
vnc = readcell(filename,'Range',[2 1]);
calculate_first_digit=cellfun(@(v)v(1),""+vnc)-'0';
    
[nlines,ncolumns] = size(calculate_first_digit);
c = unique(calculate_first_digit);
fprintf('Counting of the first digits in each row [Cell]:\n');
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
plot(x,benford,'--',x,relative_frequency,'Color','k')
title("Benford's law")
xlabel('Digits')
ylabel('Frequencies of each digit')
legend('Benford','Relative frequency of each digit')

% Pearson correlation for the total of flows:
[corre_benford_total,pvalue1_benford_total] = corr(relative_frequency,benford);

%Pearson correlation using Benford law for each flow: *************************************************
[corre_benford, pvalue1_benford] = corr(freq_occurance,benford);

Mad = (abs(freq_occurance-benford));
soma1=sum(Mad).'
soma = (sum(Mad)/9).'

desvio_padrao_mediana = std(Mad).'
limite_inferior = soma - desvio_padrao_mediana;
limite_superior = soma + desvio_padrao_mediana;
diferenca = (limite_superior+limite_inferior)/2;
limite2 = limite_inferior + diferenca

media_limite2 = mean(limite2)
desvio_padrao_limite2 = std(limite2)
limite_inferior_ajustado = round(media_limite2 - desvio_padrao_limite2,2);
limite_superior_ajustado = round(media_limite2 + desvio_padrao_limite2,2);

fprintf("Results for comparison with labels-Benford using MAD:\n");

fMAD_first_benford1 = fopen("flow_MAD_labels_Benford.txt","w");
 for l=1:nlines
   for y=1:1 
     if(soma(l,y) <=0.06) %0.06limite_inferior_ajustado
         fprintf(fMAD_first_benford1,'%d,0.0\n',l);
     elseif(soma(l,y) > 0.06 && soma(l,y) <= 0.12)  %0.0606limite_inferior_ajustado
         fprintf(fMAD_first_benford1,'%d,1.0\n',l); 
      elseif(soma(l,y) > 0.12) %&& soma(l,y) <= 0.0150) %0.0120 and 0.0150
           fprintf(fMAD_first_benford1,'%d,1.0\n',l);
     % elseif(soma(l,y) > 0.0150) 
     %         fprintf(fpearson_first_benford1,'%d,1.0\n',l);
      end
   end
 end
fclose(fMAD_first_benford1);


fprintf("Results for comparison with labels-Benford using Pearson:\n");
fprintf("Labels Pearson.. wait\n");
fpearson_first_benford = fopen("flow_Pearson_labels_Benford5.txt","w");
 for l=1:nlines
   for y=1:1 
     if(pvalue1_benford(l,y) <0.05) %
         fprintf(fpearson_first_benford,'%d,1.0\n',l); 
     else 
             fprintf(fpearson_first_benford,'%d,0.0\n',l);
     end
    end
 end
fclose(fpearson_first_benford);
% 

fpearson_second_benford = fopen("flow_Pearson_labels_Benford01.txt","w");
 for l=1:nlines
   for y=1:1 
     if(pvalue1_benford(l,y) < 0.1) %pvalue1_benford
         fprintf(fpearson_second_benford,'%d,1.0\n',l); % 0 - malicious I need to change
         else
         fprintf(fpearson_second_benford,'%d,0.0\n',l); % 1 - normal I need to change for future
     end
    end
 end
fclose(fpearson_second_benford);
% 
fpearson_third_benford = fopen("flow_Pearson_labels_Benford001.txt","w");
 for l=1:nlines
   for y=1:1 
     if(pvalue1_benford(l,y) < 0.01) %pvalue1_benford
         fprintf(fpearson_third_benford,'%d,1.0\n',l); 
         else
         fprintf(fpearson_third_benford,'%d,0.0\n',l); 
     end
    end
 end
fclose(fpearson_third_benford);


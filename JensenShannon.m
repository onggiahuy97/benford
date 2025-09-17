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
plot(x,benford,'--',x,relative_frequency,'Color','k')
title("Benford's law")
xlabel('Digits')
ylabel('Frequencies of each digit')
legend('Benford','Relative frequency of each digit')


% Normalizar a distribuição de Benford para que some 1
benford = benford / sum(benford);
epsilon = 1e-10;
% Array para armazenar as distâncias para cada coluna
js_distances = zeros(1, size(freq_occurance, 2));

for i = 1:size(freq_occurance, 2)
    % Extrair e normalizar a coluna atual
    col = freq_occurance(:, i) + epsilon;
    col = col / sum(col);  % Normalizar para que a soma seja 1

    % Adicionar epsilon e normalizar Benford novamente por precaução
    P = col;
    Q = benford + epsilon;
    Q = Q / sum(Q);

    % Calcular M e a distância de Jensen-Shannon
    M = 0.5 * (P + Q);
    js_distance = 0.5 * sum(P .* log(P ./ M) + Q .* log(Q ./ M));

    % Armazenar a distância calculada
    js_distances(i) = js_distance;
    js = js_distances.';
end

media_distancias = mean(js);
desvio_distancias = std(js);
limite_maximo = media_distancias + desvio_distancias;
limite_minimo = media_distancias - desvio_distancias;
classificacao = (js >= limite_minimo) & (js <= limite_maximo);  

fjs_pValues = fopen("jensen_labels.txt","w");
 for l=1:nlines
   for y=1:1 
         fprintf(fjs_pValues,'%d, %d\n',l,classificacao(l,y));
    end
 end
fclose(fjs_pValues)

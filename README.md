# Kriptos
A python program to encrypt files and to sign digitally files using criptography methods. The methods used here are RSA and El Gamal.
 

                                                        
            Trabalho Final de Criptografia              
                                                        
          Criptografia com RSA e/ou El Gamal            
           Assinatura digital com El Gamal              
                                                        
          Elaborado por Willian Gomes Pessoa            
            (Ciência da Computação - UFRJ)             
                                                        
      Matéria de Criptografia e Teoria dos Números      
             Inteiros - Professor Menascher             

 
 <h3> GERAÇÃO DOS NÚMEROS PRIMOS </h3>

 <b>Algoritmo(s) Utilizado(s)</b>: Miller Rabin

 <b>Decrição</b>: O método gera um número randômico conforme a
 quantidade de bits que receber como argumento (padrão =
 128).

 <b>Método principal</b>: generatePrimeNumber
 Método(s) auxiliar(es): millerRabinUnitTest, MillerRa-
 binMultiTest, randint, getrandbits

 <b>Justificativas</b>: Por questões de usabilidade, optei por
 usar um método de Miller Rabin. Por mais que este mét-
 não me dê 100% de certeza sobre a primalidade do núme-
 ro testado, é melhor obter que tem probabilidade de 99%
 de ser primo e que é obtido rapidamente, do que demorar
 dias para obter um número que é com certeza primo.

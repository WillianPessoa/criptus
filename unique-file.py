# -*- coding: utf-8 -*-

# *********************************************************
# *                                                       *
# *           Trabalho Final de Criptografia              *
# *                                                       *
# *         Criptografia com RSA e/ou El Gamal            *
# *          Assinatura digital com El Gamal              *
# *                                                       *
# *         Elaborado por Willian Gomes Pessoa            *
# *           (Ciência da Computação - UFRJ)              *
# *                                                       *
# *     Matéria de Criptografia e Teoria dos Números      *
# *            Inteiros - Professor Menascher             *
# *                                                       *
# *********************************************************



# GERAÇÃO DOS NÚMEROS PRIMOS
#
# ALGORITMO(S) UTILIZADO(S): Miller Rabin
#
# DESCRIÇÃO: O método gera um número randômico conforme a
# quantidade de bits que receber como argumento (padrão =
# 128).
#
# MÉTODO PRINCIPAL: generatePrimeNumber
# MÉTODO(S) AUXILIAR(ES): millerRabinUnitTest, MillerRa-
# binMultiTest, randint, getrandbits
#
# JUSTIFICATIVA: Por questões de usabilidade, optei por
# usar um método de Miller Rabin. Por mais que este mét-
# não me dê 100% de certeza sobre a primalidade do núme-
# ro testado, é melhor obter que tem probabilidade de 99%
# de ser primo e que é obtido rapidamente, do que demorar
# dias para obter um número que é com certeza primo.


import random
from random import randint
import math

# DESCRIÇÃO DO MÉTODO
#
#   1 - GERA UM NÚMERO DE XX ALGARISMOS
#   2 - VERIFICA SE ELE É PRIMO
#   3 - SE FOR PRIMO, GERA O NÚMERO DE MERSENNE;
#   4 - TESTA O NÚMERO DE MERSENE
#   5 - RETORNA O NÚMERO

def millerRabinUnitTest(n, b = 2):
    k = 0
    q = n - 1
    while q % 2 == 0:
        k = k + 1
        q = q/2
    t = pow(b, q) % n
    if t == 1 or t == (-1 % n):
        return False
    for i in range(0, k):
        t = pow(t, 2) % n
        if t == n - 1:
            return False
    return True

def millerRabinMultiTest(n, bases = 10):
    assert(n > 10)
    usedBases = []
    for i in range(0, 10):
        b = randint(2, n-1)
        while (b in usedBases):
            b = randint(2,n-1)
        usedBases.append(b)
        if millerRabinUnitTest(n, b):
            return False
    return True
    

def generatePrimeNumber(bits = 128):
    pseudoPrime = getrandbits(bits)
    millerRabinMultiTest(pseudoPrime)
	# TODO: Não finalizado


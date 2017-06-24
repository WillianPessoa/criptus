# -*- coding: utf-8 -*-

debug = True

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

from random import getrandbits
from random import randint
import math

import time

# @Brief Exponenciação modular.
# @Arg1 -> Base a ser testada.
# @Arg2 -> Expoente da base.
# @Arg3 -> Valor do módulo.
# @Arg4 -> Resto (padrão/inicial = 1).
# @Return -> Retorna o resto da exponenciação modular.
# TODO: Testar essa função e substituir as funções de potenciação
#       modular padrão do python por essas.
def expMod(number, exp, mod, rest = 1):
    if exp == 0:
        return rest
    else:
        if exp & 1:
            rest = (rest * number) % mod
            exp = (exp - 1) / 2
        else:
            exp = exp / 2
        number = (number * number) % mod
        modExpStepByStep(number, exp, mod, rest)


# @Brief Teste de Miller Rabin. Verifica se o número inteiro n
#        passado como argumento é primo.
# @Arg1 -> Número a ser testado.
# @Arg2 -> Base a ser utilizada par ao teste (padrão = 2).
# @Return -> False se Pseudoprimo ou True se Composto.
def millerRabinUnitTest(n, b = 2):
    assert(n >= 2)
    k = 0
    q = n - 1
    while q % 2 == 0:
        k = k + 1
        q = q/2
    t = pow(b, q, n)
    if t == 1 or t == (-1 % n):
        return False
    for i in range(0, k):
        t = pow(t, 2, n)
        if t == n - 1:
            return False
    return True

# @Brief Realiza o teste de Miller Rabin para diversas.
# @Arg1 -> Número a ser testado.
# @Arg2 -> Quantidade de bases para testar (padrão = 10).
# @Return -> False se composto ou True se PseudoPrimo.
def millerRabinMultiTest(n, bases = 10):
    usedBases = []
    for i in range(2, 10):
        b = randint(2, n-1)
        while (b in usedBases):
            b = randint(2, n-1)
        usedBases.append(b)
        if millerRabinUnitTest(n, b):
            return False
    return True
    
# @Brief Retorna um número possívelmente primo.
# @Arg1 -> Tamanho, em bits, do primo a ser gerado (padrão = 128).
# @Return -> Um possível número primo de tamanho igual ao seu argumento.
def generatePossiblePrime(bits = 128):
    possiblePrimeNumber = getrandbits(bits) 
    while not millerRabinMultiTest(possiblePrimeNumber):
        possiblePrimeNumber = getrandbits(bits)
    return possiblePrimeNumber

# @Brief 
# @Arg1 -> 
# @Arg2 -> 
# @Return ->
# TODO: Criar uma função própria para o cálculo do mdc.
def euclides_recursivo_mdc(dividendo, divisor):
    if divisor == 0:
        return dividendo
    else:
        return euclides_recursivo_mdc(divisor, dividendo % divisor)

# @Brief Busca o inverso do arg1 módulo arg2 pelo alg. euclidiano extendido.
# @Arg1 -> Primo
# @Arg2 -> Primo
# @Return -> Retorna o inverso do arg1 em "arg1 módulo arg2".
def getInverse(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    assert(b == 1)
    return x0

# @Brief Aplica o algorítmo euclidiano extendido e verifica se são primos entre si
#        ou, em outras palavras, se um número arg1 tem inverso em módulo arg2. 
# @Arg1 -> 
# @Arg2 -> 
# @Return -> True se MDC(arg1,arg2)=1 ou False se MDC(arg1, arg2)!=1  

def hasInverse(b, n):
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    if b == 1:
        return True
    return False

# @Brief Calcula o segundo valor da chave de encriptação(e),que será
#        o menor primo p onde o MDC entre p e Fi de N é igual a 1.
# @Arg1 -> fiN
# @Return -> Retorna a segundo valor da chave pública (e).
def getKeyE(fiN):
    e = 2
    while not hasInverse(e, fiN):
        e = e +1
    return e

# @Brief Calcula o segundo valor da chave de decriptação(d).
# @Arg1 -> Segundo valor da chave de encriptação(e).
# @Arg2 -> Valor da função totiente (fiN) do N usado para cálcular e.
# @Return -> Retorna a forma reduzida de d módulo fiN.
def getKeyD(e, fiN):
    return getInverse(e,fiN) % fiN

# @Brief Calcula os valores da chave pública (n, e) e privada(n, d) 
# @Arg1 -> Primo de 128 bits de tamanho.
# @Arg2 -> Primo de 128 bits de tamanho.
# @Return -> Retorna os alores da chave pública (n, e) e prívada (n,d)
#            na ordem n, e, d.
def keysRSA(p, q):
    n = p * q
    fiN = (p-1) * (q-1)
    e = getKeyE(fiN)
    d = getKeyD(e, fiN)
    return n, e, d

def Teste1(): 
    start_time = time.time()
    n = generatePossiblePrimeNumber(256)
    print n
    if millerRabinMultiTest(29):
        print "PRIMO"
    else:
        print "COMPOSTO"
    print "%.2f" % (time.time() - start_time)


def Teste2():
    keysRSA(generatePossiblePrime(),generatePossiblePrime())

Teste2()

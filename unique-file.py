# -*- coding: utf-8 -*-
#!/usr/bin/python

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
from hashlib import sha224
import math
import sys

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
        expMod(number, exp, mod, rest)


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
    assert(n >= 2)

    if bases > n:
        b = bases - n
    
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
# @Return -> Retorna os valores da chave pública (n, e) e prívada (n,d)
#            na ordem n, e, d.
def keysRSA(p, q):
    n = p * q
    fiN = (p-1) * (q-1)
    e = getKeyE(fiN)
    d = getKeyD(e, fiN)
    return n, e, d

# @Brief Encripta um bloco de bytes utilizando o RSA.
# @Arg1 -> Bloco, em bytes, a ser encriptado.
# @Arg2 -> Primeiro componente da chave pública (n)
# @Arg3 -> Segundo componente da chave pública (e)
# @Return -> Retorna o bloco de bytes encriptado.
# TODO: Enquanto o método de leitura de bytes de um arquivo não é feito,
#       o método trabalhará com um número inteiro para encriptar pela
#       questão dos testes.
def encryptionRSA(toEncrypt, n, e):
    return pow(toEncrypt, e, n)

# @Brief Decripta um bloco de bytes utilizando o RSA.
# @Arg1 -> Bloco, em bytes, a ser decriptado.
# @Arg2 -> Primeiro componente da chave privada (n)
# @Arg3 -> Segundo componente da chave privada (d)
# @Return -> Retorna o bloco de bytes decriptado.
# TODO: Enquanto o método de leitura de bytes de um arquivo não é feito,
#       o método trabalhará com um número inteiro para encriptar pela
#       questão dos testes.
def decryptionRSA(toDecrypt, n, d):
    return pow(toDecrypt, d, n)

# @Brief Pré-codifica a mensagem/arquivo para encriptação.
# @Arg1 -> Mensagem/arquivo não pré-codificado.
# @Return -> Mensagem/arquivo pré-codificado como lista de pedaços do arquivo/mensagem.
def precoding(toCode):
    blocks = []
    for i in toCode:
        blocks.append(ord(i))
    return blocks

# @Brief Decodifica mensagem após decriptação.
# @Arg1 -> Mensagem/arquivo pré-codificado.
# @Return -> Mensagem/arquivo decodificado no formato original.    
def poscoding(toDecode):
    decoded = ""
    for i in toDecode:
        decoded = decoded + chr(i)
    return decoded
    

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
    keysRSA(83,87)


def Teste3():
    
    message = "Hoje eu vou foder aquele JC! Tu vai ver, ele ta fodido, Borel! Tu vai ver!"
#    message = "Marcelle S2"

    print "Mensagem:"
    print message

    print ""
    
    print "Mensagem codificada"
    codedMessage = precoding(message)
    print codedMessage

    print ""
    
    n, e, d = keysRSA(generatePossiblePrime(), generatePossiblePrime())
    encryptedMessage = []
    for i in codedMessage:
        encryptedMessage.append(encryptionRSA(i, n, e))
    print "Mensagem criptografada com RSA"
    print encryptedMessage

    print ""

    decryptedMessage = []
    for i in encryptedMessage:
        decryptedMessage.append(decryptionRSA(i, n, d))
    print "Mensagem descriptografada"
    print decryptedMessage

    print ""

    encodedMessage = poscoding(decryptedMessage)
    print "Mensagem decodificada"
    print encodedMessage

def u(n):
    elements = []
    for element in range(1, n):
        if hasInverse(element, n):
            elements.append(element)
    return elements

# TODO remover e fazer com que o método de fatorização verifique se é primo
#      pelo método de Miller Rabin.
def isPrime(n):
    for i in range(2, n):
        if n % i == 0:
            return False
    return True

def findNextPrime(n):
    n+=1
    while True:
        if isPrime(n):
            return n;
        n = n + 1

def factorization(n):
    factors = []
    prime = 2
    while n != 1:
        if n % prime == 0:
            factors.append(prime)
            n/=prime
        else:
            prime = findNextPrime(prime)
    return factors

# Algoritmo de Gauss
def gauss(p):
    fList = factorization(p-1)
    fSet = set(fList)
    pLessOne = p-1
    g = 1
    for qi in fSet:
        a = 2 
        while pow(a, pLessOne/qi) % p == 1:
            a = a + 1
        h = pow (a, (pLessOne / pow (qi, fList.count(qi))), p)
        g = h*g % p
    return g

# @Brief Gera um primp P e o gerador G para o método El Gamal.
# @Arg1 -> tamanho do número Q que gerará P e G, sem fazer uso
#          do método de Gauss.
# @Return -> Retorna um Primo P e um gerador G. 
def generatePrimeAndGeneratorToElGamal(bits = 255):
    q = getrandbits(bits) 
    while True:
        while not millerRabinMultiTest(q):
            q = getrandbits(bits)
        p = 2*q + 1
        if millerRabinMultiTest(p):
            break
        q = getrandbits(bits)
    g = 2
    while pow(g, q, p) == 1:
        g = g + 1
    return p, g

# @Brief Gera todas as chaves necessárias para o método El Gamal.
# @Return -> Retorna chaves para o método El Gamal.  
def keysElGamal():
    p, g = generatePrimeAndGeneratorToElGamal()
    d = randint(2, p-2)
    c = pow(g, d, p)
    return p, g, c, d

# @Brief Encripta um bloco de bytes utilizando o El Gamal.
# @Arg1 -> Bloco, em bytes, a ser encriptado.
# @Arg2 -> Primeiro componente da chave pública (p).
# @Arg3 -> Segundo componente da chave pública (g).
# @Arg4 -> Terceiro componente da chave pública (c).
# @Return -> Retorna o bloco de bytes encriptado.
# TODO: Enquanto o método de leitura de bytes de um arquivo não é feito,
#       o método trabalhará com um número inteiro para encriptar pela
#       questão dos testes.
def encryptionElGamal(toEncrypt, p, g, c):
    print "Calculando k..."
    k = randint(2, 100) # Explicar isso
    s = pow(g, k, p)
    t = (toEncrypt * pow(c,k)) % p
    return (s, t)

# @Brief Decripta um bloco de bytes utilizando o El Gamal.
# @Arg1 -> Bloco (s,t) a ser decriptado.
# @Arg2 -> Primo para decodificação (p)
# @Arg3 -> Componente da chave privada para decriptação (d)
# @Return -> Retorna o bloco de bytes decriptado.
# TODO: Enquanto o método de leitura de bytes de um arquivo não é feito,
#       o método trabalhará com um número inteiro para encriptar pela
#       questão dos testes.
def decryptionElGamal(toDecrypt, p, d): #toDecrypt = (s, t)
    s = pow(getInverse(toDecrypt[0], p), d , p)
    return s * toDecrypt[1] % p

def Teste4():
    print factorization(36)

def Teste5():
    
    message = "Hoje eu vou foder aquele JC! Tu vai ver, ele ta fodido, Borel! Tu vai ver!"
#    message = "c"
    
    print "Mensagem:"
    print message

    print ""
    
    print "Mensagem codificada"
    codedMessage = precoding(message)
    print codedMessage

    print ""
    
    p, g, c, d = keysElGamal()
    print "Chaves obtidas"
    print ("p", p)
    print ("g", g)
    print ("c", c)
    print ("d", d)
    print ""
    encryptedMessage = []
    for i in codedMessage:
        encryptedMessage.append(encryptionElGamal(i, p, g, c))
    print "Mensagem criptografada com ElGamal"
    print encryptedMessage

    print ""

    decryptedMessage = []
    for i in encryptedMessage:
        decryptedMessage.append(decryptionElGamal(i, p, d))
    print "Mensagem descriptografada"
    print decryptedMessage

    print ""

    encodedMessage = poscoding(decryptedMessage)
    print "Mensagem decodificada"
    print encodedMessage

def keysDigitalSignatureElGamal():
    p, g = generatePrimeAndGeneratorToElGamal()
    a = randint(2, p-2)
    v = pow(g, a, p)
    return p, g, a, v

def digitalSignatureElGamal(p, g, a, message):
    k = randint(2, p-2)
    while not hasInverse(k, p-1):
        k = randint(2,p-2)
    r = pow(g, k, p)
    s = (getInverse(k, p-1) * int(sha224(message).hexdigest(), 16)) % p-1
    return (r,s) 

def checkDigitalSignatureElGamal(p, g, v, message, digitalSignature):
    r = digitalSignature[0]
    s = digitalSignature[1]
    if not r >= 1 and r <= p-1:
        return False
    u1 = ( pow(v, r, p)*pow(r, s, p) ) % p
    u2 = pow(g, int(sha224(message).hexdigest(), 16), p)
    if u1 != u2:
        return False
    return True
    

def Teste6():

    message = "Marcelle"
    
    print "Gerando chaves..."
    p, g, a, v = keysDigitalSignatureElGamal()

    print "Criando assinatura digital..."
    digitalSignature = digitalSignatureElGamal(p, g, a, message)

    print "Testando a assinatura digital com os valores verdadeiros..."
    result = checkDigitalSignatureElGamal(p, g, v, message, digitalSignature)
    if result:
        print "Deu certo!"
    else:
        print "Deu errado"
        
    print "Testando a assinatura digital com os valores falsos..."

def file_split(f, delim='-', bufsize=1024):
    prev = ''
    while True:
        s = f.read(bufsize)
        if not s:
            break
        split = s.split(delim)
        if len(split) > 1:
            yield prev + split[0]
            prev = split[-1]
            for x in split[1:-1]:
                yield x
        else:
            prev += s
    if prev:
        yield prev

# Principais métodos

def encryption(encryptionMethod, fileToEncrypt):
    
    fileEncrypted = open( "E" + fileToEncrypt.name.replace(".*", ""), "w")

    byte = fileToEncrypt.read(1)
    byteEncripted = 0

    n, e, d = keysRSA(generatePossiblePrime(), generatePossiblePrime())

    print ""
    print "Chaves criptográficas:"
    print "\tn = %d" % (n)
    print "\te = %d" % (e)
    print "\td = %d" % (d)
    
    while byte != "":
        #print(byte, '{0:08b}'.format(ord(byte)), ord(byte))
        byteEncrypted = encryptionRSA(ord(byte), n, e)
        #print (long(byteEncrypted), '{0:08b}'.format(byteEncrypted))
        #print ""
        fileEncrypted.write("%ld" % long(byteEncrypted))
        fileEncrypted.write("-")
        byte = fileToEncrypt.read(1)

def decryption(encryptionMethod, fileToDecrypt):
    fileDecrypted = open( "D" + fileToDecrypt, "wb")

    print "Insira as chave descriptográfica n:"
    n = input()
    print "insira a chave descriptográfica d:"
    d = input()

    for i in file_split(open(fileToDecrypt)):
        print chr(decryptionRSA(int(i), n, d))

def signatureFile(signatureMethod):
    something = 0

def encryptionAndSignatureFile(encryptionMethod, fileToEncrypt):
    something = 0

def decryptionAndSignatureCheck(encryptionMethod, fileToDecrypt):
    something = 0

def identifyEncryptionMethod(arg):
    if arg == "rsa" or arg == "elgamal":
        return arg
    else:
        return "desconhecido"
    
# Passing args to a list and removing fist element (name of this file)
args = list(sys.argv)
args.remove(args[0])

allDone = False

i = 0
while not allDone:
    if args[i] == "unieque-file.py":
        i += 1
    elif args[i] == "--encrypt":
        i += 1
        encryptionMethod = identifyEncryptionMethod(args[i])
        print "Modo de encriptação %s" % (encryptionMethod)
        if encryptionMethod == "desconhecido":
           break
        i += 1
        fileToEncrypt = open(args[i], "rb")
        print "Encripitando o arquivo %s" % (fileToEncrypt.name)
        encryption(encryptionMethod, fileToEncrypt)
        allDone = True
    elif args[i] == "--decrypt":
        i += 1
        decryptionMethod = identifyEncryptionMethod(args[i])
        print "Modo de encriptação %s" % decryptionMethod
        if decryptionMethod == "desconhecido":
            break
        i += 1
        fileToDecrypt = args[i]
        print "Decripitando o arquivo %s" % (fileToDecrypt)
        decryption(decryptionMethod, fileToDecrypt)
        allDone = True
    elif args[i] == "--sign":
        i += 1
        print "assinatura digital"
        break
    elif "--combinados":
        i += 1
        print "assinatura digital"
        break
if allDone ==  False:
    print "O programa será encerrado por falta de argumentos"
        

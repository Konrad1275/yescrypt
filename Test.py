from yescrypt import *
from unicodedata import name
import time

if __name__ == '__main__':
    password = "przyklad"
    salt = "semestru"
    print("dla hasła \033[1m"+password+"\033[0m i soli \033[1m"+salt+"\033[0m")
    t0 = time.time()
    skrot = calculate(bytes(password.encode()), bytes(salt,'utf-8'), 4, 2, 2, 0, 0, YESCRYPT_PREHASH, 9)
    print("generowanie zajeło "+str(time.time()-t0)+" sekund")
    print(skrot)
    u = skrot.decode('charmap')
    print(u)
    # for i in range(0,len(u)):
    #     print(name(chr(u[i])))

# Password – A byte array of arbitrary length.              Ciąg bitów dowolnej długości
# Salt – A byte array of arbitrary length.                  Ciąg bitów dowolnej długości
# N – An integer power of two, strictly greater than 1.     całkowita potęga dwójki większa od 1
# R – An integer strictly greater than zero.                liczba całkowita dodatnia
# P – An integer strictly greater than zero.                liczba całkowita dodatnia
# T – An integer greater than or equal to zero.             liczba całkowita nieujemna
# G – An integer greater than or equal to zero.             liczba całkowita nieujemna
# Flags – Valid flags are: YESCRYPT_RW, YESCRYPT_WORM and YESCRYPT_PREHASH. Each flag can either be set or not set.
# Prawidłowe flagi to YESCRYPT_RW, YESCRYPT_WORM and YESCRYPT_PREHASH. Każda flaga może być ustatwiona bądź nie
# DKLen – The length of key to derive (output).             liczba znaków wyjśćia

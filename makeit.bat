:: https://github.com/x86ptr/apiresolver
:: 32-bit

@echo off

ml /c /coff /W2 ./src/apiresolver.asm

cl -EHsc /W2 /O2 ./src/main.cpp apiresolver.obj

del apiresolver.obj
del main.obj 

pause
cls

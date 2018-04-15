# gpw: Password Generator
This package generates pronounceable passwords. It uses the statistics of three-letter combinations (trigraphs) taken from whatever dictionaries you feed it. Thus pronouceability may differ from language to language. It is based on the ideas in Morrie Gasser's password generator for Multics, and Dan Edwards's generator for CTSS. (Weaknesses in Gasser-like password generators were found in the 1990s. See the 1994  "A New Attack on Random Pronounceable Password Generators" by Ravi Ganesan and Chris Davies.) Don't use this generator blindly. (My programs are in C++ but are trivially convertible to C, just remove the word const.)



## gpw.c
Generate passwords. Execute
```
      gpw [npasswords] [passwordlenth]
```
To generate pronounceable passwords. Default is 10 passwords of length 8.

`gpw.c` #includes a big table of constants from trigram.h giving frequencies.

## oadtris.c
Generates `trigram.h ` from your dictionaries.

## Makefile
Compiles gpw for your system.

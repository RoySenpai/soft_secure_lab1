# Introduction to Software Security Assignment (Laboratory) 1 
### For Computer Science B.S.c Ariel University

**By Roy Simanovich**

## Description
This is a demonstration of ELF executable editing, and how to hijack a function via shared library. We edited our ELF executable (secret->secret_hacked) to load our custom shared library (.so.6), such that the scanf function will do some other stuff beside just putting the user input to variables.

## Requirements
* Linux machine
* GNU C Compiler
* Make
* Hexeditor

## Building
```
# Cloning the repo to local machine.
git clone https://github.com/RoySenpai/soft_secure_lab1.git

# Building all the necessary files & the main programs.
make all

# Export shared libraries.
export LD_LIBRARY_PATH="."
```

## Running
```
# Run the main program.
./secret

# Run the server side.
./server

# Run the hijacked program.
./secret_hacked
```
import argparse
import os
import sys
import time
import readline

#modules
from modules.scanner import scanner

COMMANDS = {
    "fileScanner" : (scanner, "File Scanner ")
}

def Help():
    print("olá")

def Terminal():
    while True:
        try:
            user_input = str(input("ZeroShield >> ")).strip()
            if not user_input:
                continue
            parts = user_input.split()
            command = parts[0].lower()
            arguments = parts[1:]
            
            if command in COMMANDS:
                COMMANDS[command][0](arguments)
            
            elif command in ["quit", "exit"]:
                time.sleep(1)
                print("ZeroShield > Exiting the program")
            elif command == "clear":
                os.system("clear")
            elif command == "help":
                Help()
            else:
                print(f"[ERROR] Unknown command: '{command}'. Type 'help' for available commands.")

        except SystemError:
            pass
        except KeyboardInterrupt:
            print("ZeroShiel > Exiting the program")
        except EOFError:
            print("ZeroShiel > Exiting the program")
        
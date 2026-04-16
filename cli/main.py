import argparse
import os
import sys
import time
import readline

#File Path Resolver
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

#Modules
from modules.scanner import scanner

COMMANDS = {
    "scanner" : (scanner, "File Scanner ")
}

def Help():
    for command, (_, descritions) in COMMANDS.items():
        print(f"{command:}   {descritions}")
    print("  help            Show this help message")
    print("  quit / exit     Exit the program\n")

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
            exit()
        except EOFError:
            print("ZeroShiel > Exiting the program")
            exit()
        
def main():
    Terminal()
if __name__ == "__main__":
    main()
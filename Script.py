import os
from pwn import log
import hashlib  # Import hashlib to calculate SHA-256 hashes


def show_banner():
    banner = r"""
                       ______
                    .-"      "-.
                   /  *ViRuS*   \
       _          |              |          _
      ( \         |,  .-.  .-.  ,|         / )
       > "=._     | )(_0_/\_0_)( |     _.=" <
      (_/"=._"=._ |/     /\     \| _.="_.="\_)
             "=._ (_     ^^     _)"_.="
                 "=\__|IIIIII|__/="
                _.="| \IIIIII/ |"=._
      _     _.="_.="\          /"=._"=._     _
     ( \_.="_.="     `--------`     "=._"=._/ )
      > _.="                            "=._ <
     (_/                                    \_)
 ____________________________________________________
 ----------------------------------------------------        
        #  SHA256 Hash Cracker
        #  Author : The-Real-Virus
        #  https://github.com/The-Real-Virus
 ____________________________________________________
 ----------------------------------------------------
"""
    print(banner)


def sha256sumhex(password):
    """Compute SHA-256 hash of a password."""
    return hashlib.sha256(password).hexdigest()


def main():
    show_banner()

    choice = input("\nPress 'y' to continue or 'n' to exit: ").strip().lower()

    if choice == 'n':
        print("\nExiting the script. Goodbye!")
        return

    elif choice == 'y':
        os.system('clear' if os.name == 'posix' else 'cls')  # 'clear' for Linux/Mac, 'cls' for Windows

        # Take the hash input from the user
        wanted_hash = input("Enter the SHA256 hash to crack: ").strip()

        # Check if the user provided a valid hash
        if len(wanted_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in wanted_hash):
            print("Invalid SHA256 hash. Please enter a valid 64-character hexadecimal string.")
            return

        password_file = "rockyou.txt"
        attempts = 0

        with log.progress("Attempting To Crack: {}!\n".format(wanted_hash)) as p:
            try:
                with open(password_file, 'r', encoding='latin-1') as password_list:
                    for Password in password_list:
                        password = Password.strip("\n").encode('latin-1')
                        password_hash = sha256sumhex(password)
                        p.status("[{}] {} == {}".format(attempts, password.decode('latin-1'), password_hash))

                        if password_hash == wanted_hash:
                            p.success(
                                "Password Hash Found After {} Attempts! [>>> {} <<<] ".format(
                                    attempts, password.decode('latin-1')
                                )
                            )
                            return

                        attempts += 1

                    p.failure("Password Hash Not Found!")

            except FileNotFoundError:
                print("Password file '{}' not found. Please ensure the file exists.".format(password_file))

    else:
        print("\nInvalid choice. Exiting the script.")


if __name__ == "__main__":
    main()

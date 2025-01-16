# SHA256 Hash Cracker

## 📜Description
A Python script to crack SHA256 hashes using a password list.  
This tool is built for educational and ethical purposes only.  

## 🔑Features
- Uses the `rockyou.txt` password file (or any custom password file) to brute-force SHA256 hashes.  
- Displays a progress log with each attempt.  
- Exits gracefully if the hash is not found.  

## 🚀Step-by-Step Guide in Linux Terminal !

Step 1: Update & upgrade your system  
>sudo apt update  
>sudo apt upgrade  

Step 2: Clone the repository  
>git clone https://github.com/The-Real-Virus/SHA256-Hash-Cracker.git  

Step 3: Go to the Tool Directory where u clone it and read requirements.txt file !  
>cd SHA256-Hash-Cracker    
(read requirements.txt file using cat or gedit)  

Step 4: extract the rockyou file using unrar  
>sudo apt install unrar (if it is not installed in ur kali linux)  
>unrar x rockyou.rar  

Step 5: After Completing the process now u can run script  
>python3 Script.py  

## ⚙️Troubleshooting
1) `Missing :` 'rockyou.txt' file: If the script doesn't find the rockyou.txt file, make sure it is in the same
directory or specify the full path in the script.

2) `Permission Denied:` Ensure the script is run with the necessary privileges.

3) `Pwn Module Error :` If the pwn module is not installed, install it ( see requirements.txt for commands )

## 🤝Follow the Prompts !
- You’ll see a banner with the script's details.  
- Enter a valid SHA256 hash when prompted (64-character hexadecimal string).  
- The script will start attempting to crack the hash using the rockyou.txt file.  
- If the password is found, it will be displayed along with the number of attempts.  
- If not found, the script will notify you after exhausting the password list.  

## 🛠️MODIFICATION ( use own wordlist )

if u want to use ur own wordlist instead of rockyou.txt , u can modify in the script ,  

Step 1: create ur own wordlist  

Step 2: move it into the SHA256-Hash-Cracker Directory ( deleting rockyou is not necessory )  

Step 3: open the script in any editor , i use gedit ( `gedit Script.py` ),
( if not installed then run `sudo apt install gedit` )

Step 4: Find These Lines,  

          # Take the hash input from the user
          wanted_hash = input("Enter the SHA256 hash to crack: ").strip()

          # Check if the user provided a valid hash
          if len(wanted_hash) != 64 or not all(c in "0123456789abcdefABCDEF" for c in wanted_hash):
              print("Invalid SHA256 hash. Please enter a valid 64-character hexadecimal string.")
              return

          password_file = "rockyou.txt"
          attempts = 0

          with log.progress("Attempting To Crack: {}!\n".format(wanted_hash)) as p:

Step 5: Here u can see rockyou.txt , change the name rockyou to ur own wordlist in quotes  
example : password_file = "mylist.txt"

Step 6: Save the script and run !

# ⚠️Disclaimer !
This tool is intended for ethical and educational use only.  
Do not use it for illegal activities. The author is not responsible for any misuse.  

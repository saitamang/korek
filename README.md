# korek
korek is malay language which is stands for "Dig".

## Tools:
### I build severel tools here to cover on enumeration and priv es part:
#### 1 - copyfail-p2.py
- this one to cover part if the machine dont have python3 but python2.7, we can utilize this, i dont see anyone do this

#### 2 - copyfail.c
- as currently some machine dont have both python, copyfail exploit can be utilize using the binary itself, thus this would be helpful
- Be mindful, those copyfail only tested on kali
  ```
  # copyfail.c can be compile:
  gcc -o copyfail copyfail.c -static -lz
  ```

#### 3 - win-korek.ps1
- after running winpeas.exe, if you dont find anything, can continue with this

#### 4 - linux-korek.sh
- after running linpeas.sh, if you dont find anything, can continue with this

#### 5 - mssqli-exploit.py
- i am building this script just to identify if the endpoint is vulnerable to the mssqli as this script will check using blind sql testing, this script also can utilize the xpcmd_shell if present for RCE purpose

# Disclaimer
### I am not responsible for any misuse of this tool, this tools is use for only on the permitted env for PoC purpose and helpfull for those who are taking any exam. Cheers - SAITAMANG

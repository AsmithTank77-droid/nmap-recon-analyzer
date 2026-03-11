




# classifier.py
# Categories services discovered in Nmap scans

SERVICE_CATEGORIES = {
    "remote_access": [
        "ssh",
        "telnet",
        "rdp",
        "vnc",
        "winrm"
    ],
        "web_services": [
        "http",
        "https",
        "http-proxy",
        "http-alt"
    ],

    "file_sharing": [
        "ftp",
        "smb",
        "nfs",
        "tftp"
    ],
    "email_services": [
        "smtp",
        "pop3",
        "imap",
        "imap4"
    ],

    "insecure_services": [
        "telnet",
        "ftp",
        "tftp",
        "smb",
        "rsh",
        "rexec"
    ]
}


def classify_service(port):

    port = int(port)

    if port in [21,22,23,3389]:
        return "Remote Access"

    elif port in [80,443,8080]:
        return "Web Service"

    elif port in [445,139]:
        return "File Sharing"

    elif port in [25,110,143,993]:
        return "Email Service"

    else:
        return "Unknown"

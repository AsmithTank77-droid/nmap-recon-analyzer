# enum_suggestions.py
# Provides enumeration suggestions based on detected services

def suggest_enum(port, service):

    suggestions = {
        "Remote Access": [
            "Try SSH enumeration: nmap --script ssh-auth-methods",
            "Check for weak credentials or brute force"
        ],

        "Web Service": [
            "Run directory enumeration with gobuster",
            "Check technologies with whatweb",
            "Look for common web vulnerabilities"
        ],

        "File Sharing": [
            "Enumerate SMB shares with smbclient",
            "Use enum4linux for deeper enumeration"
        ],

        "Email Service": [
            "Enumerate SMTP users with smtp-user-enum",
            "Check for open mail relay"
            ],
 }


    return suggestions.get(service, ["No specific enumeration suggestions"])





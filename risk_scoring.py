def calculate_risk(port, service):

    if port in [21, 22, 23]:
        return "High"

    elif port in [80, 443]:
        return "Medium"

    else:
        return "Low"

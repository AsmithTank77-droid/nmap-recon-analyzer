# risk_engine.py

def calculate_risk(port):

    port = int(port)

    if port in [22,3389]:
        return "High"

    elif port in [21,23]:
        return "Critical"

    elif port in [80,443]:
        return "Medium"

    elif port in [445,139]:
        return "High"

    else:
        return "Low"

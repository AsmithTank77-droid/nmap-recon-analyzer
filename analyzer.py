import sys

def analyze_nmap(file):
    with open(file, "r") as f:
        lines = f.readlines()

    print("Open Ports Found:\n")

    for line in lines:
        if "/tcp" in line and "open" in line:
            print(line.strip())

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python analyzer.py scan.txt")
        sys.exit()

    analyze_nmap(sys.argv[1])

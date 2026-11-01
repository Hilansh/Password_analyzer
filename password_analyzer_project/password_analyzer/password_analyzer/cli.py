import argparse, getpass, json
from .analyzer import analyze_password

def main():
    parser = argparse.ArgumentParser(description="Offline password strength analyzer")
    parser.add_argument("--json", action="store_true", help="print machine-readable JSON")
    parser.add_argument("--context", nargs="*", default=[], help="optional context words to check")
    args = parser.parse_args()
    password = getpass.getpass("Enter password (input is hidden): ")
    result = analyze_password(password, args.context)
    data = result.to_dict()
    if args.json:
        print(json.dumps(data, indent=2, ensure_ascii=False))
        return
    print(f"\\nStrength: {result.rating} ({result.score}/100)")
    print(f"Length: {result.length} | Character-pool estimate: {result.entropy_bits} bits")
    print("\\nCharacter types:")
    for name, present in result.character_types.items():
        print(f"  {name.title():12}: {'Yes' if present else 'No'}")
    print("\\nFindings:")
    for item in result.findings: print(f"  - {item}")
    print("\\nRecommendations:")
    for item in result.recommendations: print(f"  - {item}")
    print("\\nPrivacy: password analyzed locally; this tool does not save or transmit it.")
if __name__ == "__main__": main()

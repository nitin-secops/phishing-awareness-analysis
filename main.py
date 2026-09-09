"""
main.py
-------
Entry point for the Phishing Awareness Analysis tool.

Two modes:
  1. Analyze a single email (paste text or point to a file)
  2. Batch-analyze every sample in the samples/ folder and print a
     summary table - similar to how a SOC analyst triages a queue
     of flagged messages.
"""

import os

from report_generator import generate_report, combine_findings

SAMPLES_DIR = os.path.join(os.path.dirname(__file__), "samples")


def analyze_single_file():
    filename = input("Enter path to email file (or press Enter to paste text): ").strip()

    if filename:
        try:
            with open(filename, "r", encoding="utf-8") as f:
                raw_email = f.read()
        except FileNotFoundError:
            print(f"File not found: {filename}")
            return
    else:
        print("Paste the raw email (headers + body). Type 'END' on its own line when done:")
        lines = []
        while True:
            line = input()
            if line.strip() == "END":
                break
            lines.append(line)
        raw_email = "\n".join(lines)

    print()
    print(generate_report(raw_email, case_id=os.path.basename(filename) or "manual-input"))


def batch_analyze_samples():
    if not os.path.isdir(SAMPLES_DIR):
        print(f"No samples folder found at {SAMPLES_DIR}")
        return

    sample_files = sorted(
        f for f in os.listdir(SAMPLES_DIR) if f.endswith(".txt")
    )

    if not sample_files:
        print("No sample files found in samples/.")
        return

    print(f"\nAnalyzing {len(sample_files)} sample messages...\n")
    print(f"{'File':<30} {'Verdict':<18} {'Score':<6}")
    print("-" * 56)

    for filename in sample_files:
        path = os.path.join(SAMPLES_DIR, filename)
        with open(path, "r", encoding="utf-8") as f:
            raw_email = f.read()

        result = combine_findings(raw_email)
        print(f"{filename:<30} {result['final_verdict']:<18} {result['total_score']:<6}")

    print("\nRun a single analysis (option 1) for full details on any message.")


def main():
    print("=== Phishing Awareness Analysis Tool ===")

    while True:
        print("\nChoose an option:")
        print("1. Analyze a single email")
        print("2. Batch-analyze all samples")
        print("3. Quit")

        choice = input("Enter choice (1/2/3): ").strip()

        if choice == "1":
            analyze_single_file()
        elif choice == "2":
            batch_analyze_samples()
        elif choice == "3":
            print("Exiting. Stay vigilant!")
            break
        else:
            print("Invalid choice, please try again.")


if __name__ == "__main__":
    main()

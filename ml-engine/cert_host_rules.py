import pandas as pd
import os
import re


# ============================================================
# SMARTVNC - CERT HOST RULE ENGINE
# Combination-Based Behavioral Risk Scoring
# ============================================================

INPUT_FILE = r"datasets\processed\cert_processed.csv"
OUTPUT_FILE = r"datasets\processed\host_risk_scores.csv"

CHUNK_SIZE = 100000


# ============================================================
# Helper Functions
# ============================================================

def is_usb_connected(value):
    value = str(value).strip().lower()

    return value in {
        "connect",
        "connected",
        "usb connect"
    }


def is_login(value):
    value = str(value).strip().lower()

    return value in {
        "logon",
        "login"
    }


def has_file(value):
    value = str(value).strip().lower()

    return value not in {
        "",
        "no file",
        "no activity",
        "nan",
        "none"
    }


def get_file_extension(filename):
    filename = str(filename).strip().lower()

    if filename in {
        "",
        "no file",
        "nan",
        "none"
    }:
        return ""

    match = re.search(r"\.([a-z0-9]+)$", filename)

    if match:
        return match.group(1)

    return ""


def has_suspicious_content(content):
    content = str(content).strip().lower()

    if content in {
        "",
        "no activity",
        "nan",
        "none"
    }:
        return False

    keywords = [
        "confidential",
        "secret",
        "password",
        "credential",
        "private",
        "sensitive",
        "database",
        "export",
        "transfer",
        "classified"
    ]

    return any(keyword in content for keyword in keywords)


# ============================================================
# Host Risk Calculation
# ============================================================

def calculate_host_risk(row):

    usb = is_usb_connected(row["usb_activity"])
    login = is_login(row["login_activity"])
    file_access = has_file(row["file_name"])
    suspicious_content = has_suspicious_content(
        row["file_content"]
    )

    extension = get_file_extension(
        row["file_name"]
    )

    score = 0
    indicators = []


    # --------------------------------------------------------
    # Rule 1: USB activity alone
    # --------------------------------------------------------

    if usb:
        indicators.append("USB activity")


    # --------------------------------------------------------
    # Rule 2: Login alone
    #
    # Login is normal context and therefore does NOT
    # contribute risk by itself.
    # --------------------------------------------------------

    if login:
        indicators.append("Login activity")


    # --------------------------------------------------------
    # Rule 3: File activity alone
    #
    # File access is normal context and does NOT contribute
    # risk by itself.
    # --------------------------------------------------------

    if file_access:
        indicators.append("File activity")


    # --------------------------------------------------------
    # Rule 4: USB + File
    #
    # Possible removable-media data transfer.
    # --------------------------------------------------------

    if usb and file_access:

        score += 35

        indicators.append(
            "USB + file activity"
        )


    # --------------------------------------------------------
    # Rule 5: USB + Login + File
    #
    # Stronger behavioral combination.
    # --------------------------------------------------------

    if usb and login and file_access:

        score += 15

        indicators.append(
            "USB + login + file activity"
        )


    # --------------------------------------------------------
    # Rule 6: Suspicious file content
    # --------------------------------------------------------

    if suspicious_content:

        score += 25

        indicators.append(
            "Suspicious content"
        )


    # --------------------------------------------------------
    # Rule 7: USB + suspicious content
    #
    # Possible transfer of sensitive information through
    # removable media.
    # --------------------------------------------------------

    if usb and suspicious_content:

        score += 15

        indicators.append(
            "USB + suspicious content"
        )


    # --------------------------------------------------------
    # Rule 8: Sensitive file types
    #
    # Supporting evidence only.
    # --------------------------------------------------------

    sensitive_extensions = {
        "doc",
        "docx",
        "xls",
        "xlsx",
        "csv",
        "pdf",
        "txt",
        "zip",
        "rar"
    }

    if extension in sensitive_extensions:

        if usb and file_access:

            score += 10

            indicators.append(
                f"Sensitive file type (.{extension})"
            )


    # --------------------------------------------------------
    # Rule 9: Strong combined behavior
    #
    # USB + Login + File + Suspicious Content
    # --------------------------------------------------------

    if (
        usb
        and login
        and file_access
        and suspicious_content
    ):

        score += 15

        indicators.append(
            "Multiple correlated suspicious activities"
        )


    # --------------------------------------------------------
    # Cap score
    # --------------------------------------------------------

    score = min(score, 100)


    # --------------------------------------------------------
    # Decision
    # --------------------------------------------------------

    if score >= 70:

        decision = "High Risk"

    elif score >= 40:

        decision = "Suspicious"

    else:

        decision = "Normal"


    # --------------------------------------------------------
    # Evidence text
    # --------------------------------------------------------

    if indicators:

        evidence = "; ".join(
            dict.fromkeys(indicators)
        )

    else:

        evidence = "No suspicious indicators"


    return score, decision, evidence


# ============================================================
# Process Chunk
# ============================================================

def process_chunk(df):

    results = []

    for _, row in df.iterrows():

        score, decision, evidence = calculate_host_risk(
            row
        )

        results.append({

            "timestamp": row["timestamp"],

            "user": row["user"],

            "computer": row["computer"],

            "host_risk_score": score,

            "host_decision": decision,

            "indicators": evidence

        })

    return pd.DataFrame(results)


# ============================================================
# MAIN
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - CERT HOST RULE ENGINE")
    print("Combination-Based Behavioral Risk Scoring")
    print("=" * 70)

    print("\nInput:")
    print(INPUT_FILE)

    print("\nProcessing CERT dataset...")

    output_chunks = []

    chunk_number = 0

    for chunk in pd.read_csv(
        INPUT_FILE,
        chunksize=CHUNK_SIZE
    ):

        chunk_number += 1

        print(
            f"Processing chunk {chunk_number}..."
        )

        result = process_chunk(chunk)

        output_chunks.append(result)


    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    final_df = pd.concat(
        output_chunks,
        ignore_index=True
    )


    # --------------------------------------------------------
    # Save
    # --------------------------------------------------------

    final_df.to_csv(
        OUTPUT_FILE,
        index=False
    )


    # --------------------------------------------------------
    # Summary
    # --------------------------------------------------------

    print("\n" + "=" * 70)
    print("HOST RULE ENGINE COMPLETED")
    print("=" * 70)

    print(
        f"\nTotal records: "
        f"{len(final_df):,}"
    )

    normal_count = (
        final_df["host_decision"] == "Normal"
    ).sum()

    suspicious_count = (
        final_df["host_decision"] == "Suspicious"
    ).sum()

    high_risk_count = (
        final_df["host_decision"] == "High Risk"
    ).sum()

    print(
        f"\nNormal: "
        f"{normal_count:,}"
    )

    print(
        f"Suspicious: "
        f"{suspicious_count:,}"
    )

    print(
        f"High Risk: "
        f"{high_risk_count:,}"
    )

    print("\nRisk Score Distribution:")

    print(
        final_df["host_risk_score"]
        .value_counts()
        .sort_index()
    )

    print("\nOutput:")
    print(OUTPUT_FILE)


if __name__ == "__main__":
    main()
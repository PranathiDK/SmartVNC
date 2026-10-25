import pandas as pd
import numpy as np

from pathlib import Path


# ============================================================
# SMARTVNC - DECISION ENGINE
# ============================================================
#
# Combines independent:
#
#   1. CERT Host Risk V2
#   2. CICIDS Network Risk
#
# IMPORTANT:
# CERT and CICIDS do NOT contain a common event/host identifier.
# Therefore this engine does NOT perform row-by-row correlation.
#
# The engine makes:
#
#   Host Decision
#   Network Decision
#   Overall Security Decision
#
# ============================================================


BASE_DIR = Path(__file__).resolve().parents[1]


# ------------------------------------------------------------
# Input files
# ------------------------------------------------------------

HOST_RISK_FILE = (
    BASE_DIR
    / "datasets"
    / "risk"
    / "host_risk_v2.csv"
)

NETWORK_RISK_FILE = (
    BASE_DIR
    / "datasets"
    / "risk"
    / "network_risk.csv"
)


# ------------------------------------------------------------
# Output
# ------------------------------------------------------------

OUTPUT_DIR = (
    BASE_DIR
    / "datasets"
    / "risk"
)

OUTPUT_DIR.mkdir(
    parents=True,
    exist_ok=True
)

OUTPUT_FILE = (
    OUTPUT_DIR
    / "decision_results.csv"
)


# ============================================================
# Thresholds
# ============================================================

LOW_THRESHOLD = 25.0
HIGH_THRESHOLD = 75.0


# ============================================================
# Convert risk score to decision
# ============================================================

def risk_to_decision(risk):

    if pd.isna(risk):
        return "INVALID_DATA"

    if risk >= HIGH_THRESHOLD:
        return "BLOCK"

    if risk >= LOW_THRESHOLD:
        return "MONITOR"

    return "ALLOW"


# ============================================================
# Main
# ============================================================

def main():

    print("=" * 70)
    print("SMARTVNC - DECISION ENGINE")
    print("=" * 70)

    # --------------------------------------------------------
    # 1. Load Host Risk
    # --------------------------------------------------------

    print("\nLoading Host Risk V2...")

    host_df = pd.read_csv(
        HOST_RISK_FILE
    )

    print(
        f"Host records: {len(host_df):,}"
    )

    # --------------------------------------------------------
    # 2. Load Network Risk
    # --------------------------------------------------------

    print("\nLoading Network Risk...")

    network_df = pd.read_csv(
        NETWORK_RISK_FILE
    )

    print(
        f"Network records: {len(network_df):,}"
    )

    # --------------------------------------------------------
    # 3. Validate required columns
    # --------------------------------------------------------

    if "host_risk" not in host_df.columns:

        raise ValueError(
            "host_risk column missing from host_risk_v2.csv"
        )

    if "network_risk" not in network_df.columns:

        raise ValueError(
            "network_risk column missing from network_risk.csv"
        )

    # --------------------------------------------------------
    # 4. Independent host decisions
    # --------------------------------------------------------

    print(
        "\nEvaluating host security decisions..."
    )

    host_df["host_decision"] = (
        host_df["host_risk"]
        .apply(risk_to_decision)
    )

    # --------------------------------------------------------
    # 5. Independent network decisions
    # --------------------------------------------------------

    print(
        "Evaluating network security decisions..."
    )

    network_df["network_decision"] = (
        network_df["network_risk"]
        .apply(risk_to_decision)
    )

    # --------------------------------------------------------
    # 6. Host security summary
    # --------------------------------------------------------

    host_block = int(
        (host_df["host_decision"] == "BLOCK").sum()
    )

    host_monitor = int(
        (host_df["host_decision"] == "MONITOR").sum()
    )

    host_allow = int(
        (host_df["host_decision"] == "ALLOW").sum()
    )

    # --------------------------------------------------------
    # 7. Network security summary
    # --------------------------------------------------------

    network_block = int(
        (network_df["network_decision"] == "BLOCK").sum()
    )

    network_monitor = int(
        (network_df["network_decision"] == "MONITOR").sum()
    )

    network_allow = int(
        (network_df["network_decision"] == "ALLOW").sum()
    )

    network_invalid = int(
        (network_df["network_decision"] == "INVALID_DATA").sum()
    )

    # --------------------------------------------------------
    # 8. Determine independent security posture
    # --------------------------------------------------------
    #
    # This is NOT event correlation.
    #
    # A BLOCK signal from either stream means the security
    # system has observed high-risk activity.
    #
    # --------------------------------------------------------

    if host_block > 0 or network_block > 0:

        overall_decision = "BLOCK"

    elif host_monitor > 0 or network_monitor > 0:

        overall_decision = "MONITOR"

    else:

        overall_decision = "ALLOW"

    # --------------------------------------------------------
    # 9. Calculate representative risk scores
    # --------------------------------------------------------

    valid_host_risk = host_df[
        "host_risk"
    ].dropna()

    valid_network_risk = network_df[
        "network_risk"
    ].dropna()

    host_max = (
        valid_host_risk.max()
        if len(valid_host_risk) > 0
        else np.nan
    )

    host_mean = (
        valid_host_risk.mean()
        if len(valid_host_risk) > 0
        else np.nan
    )

    network_max = (
        valid_network_risk.max()
        if len(valid_network_risk) > 0
        else np.nan
    )

    network_mean = (
        valid_network_risk.mean()
        if len(valid_network_risk) > 0
        else np.nan
    )

    # --------------------------------------------------------
    # 10. Create system summary
    # --------------------------------------------------------

    summary = pd.DataFrame([
        {
            "host_records": len(host_df),

            "network_records": len(network_df),

            "host_max_risk": round(
                host_max,
                2
            ),

            "host_mean_risk": round(
                host_mean,
                2
            ),

            "network_max_risk": round(
                network_max,
                2
            ),

            "network_mean_risk": round(
                network_mean,
                2
            ),

            "host_block_events": host_block,

            "host_monitor_events": host_monitor,

            "host_allow_events": host_allow,

            "network_block_events": network_block,

            "network_monitor_events": network_monitor,

            "network_allow_events": network_allow,

            "network_invalid_events": network_invalid,

            "overall_decision": overall_decision
        }
    ])

    # --------------------------------------------------------
    # 11. Save detailed host decisions
    # --------------------------------------------------------

    host_output = (
        OUTPUT_DIR
        / "host_decisions.csv"
    )

    host_df.to_csv(
        host_output,
        index=False
    )

    # --------------------------------------------------------
    # 12. Save detailed network decisions
    # --------------------------------------------------------

    network_output = (
        OUTPUT_DIR
        / "network_decisions.csv"
    )

    network_df.to_csv(
        network_output,
        index=False
    )

    # --------------------------------------------------------
    # 13. Save system summary
    # --------------------------------------------------------

    summary.to_csv(
        OUTPUT_FILE,
        index=False
    )

    # ========================================================
    # Display results
    # ========================================================

    print(
        "\n" + "=" * 70
    )

    print(
        "HOST DECISION SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"ALLOW   : {host_allow:,}"
    )

    print(
        f"MONITOR : {host_monitor:,}"
    )

    print(
        f"BLOCK   : {host_block:,}"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "NETWORK DECISION SUMMARY"
    )

    print(
        "=" * 70
    )

    print(
        f"ALLOW        : {network_allow:,}"
    )

    print(
        f"MONITOR      : {network_monitor:,}"
    )

    print(
        f"BLOCK        : {network_block:,}"
    )

    print(
        f"INVALID_DATA : {network_invalid:,}"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "SYSTEM SECURITY POSTURE"
    )

    print(
        "=" * 70
    )

    print(
        f"Host maximum risk   : {host_max:.2f}"
    )

    print(
        f"Host average risk   : {host_mean:.2f}"
    )

    print(
        f"Network maximum risk: {network_max:.2f}"
    )

    print(
        f"Network average risk: {network_mean:.2f}"
    )

    print(
        f"\nOVERALL DECISION: {overall_decision}"
    )

    print(
        "\n" + "=" * 70
    )

    print(
        "DECISION ENGINE COMPLETED"
    )

    print(
        "=" * 70
    )

    print(
        "\nGenerated files:"
    )

    print(
        f" - {host_output}"
    )

    print(
        f" - {network_output}"
    )

    print(
        f" - {OUTPUT_FILE}"
    )


if __name__ == "__main__":

    main()
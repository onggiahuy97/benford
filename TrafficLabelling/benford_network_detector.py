#!/usr/bin/env python3
"""
benford_network_detector.py

Benford's Law anomaly checker for network flow CSV datasets (e.g., CIC-IDS2017/2018, UNSW-NB15, CTU-13).
- Computes first-digit and first-two-digit distributions on selected numeric columns.
- Supports whole-dataset, per-entity (e.g., Source IP), and sliding time windows.
- Scores divergence using: MAD (mean absolute deviation), Chi-square, and Jensen-Shannon distance.
- Emits an alerts CSV and optional plots.

Usage (basic):
  python benford_network_detector.py --csv path/to/flows.csv --time-col "Timestamp" --entity-col "Source IP" \
    --cols "Flow Bytes/s" "Flow Packets/s" "Total Length of Fwd Packets" "Total Length of Bwd Packets" \
    --window "15min" --outdir out_benford

If you omit --cols, the script will auto-select likely Benford-suitable columns by name heuristics.

Notes:
- Zeros and negatives are removed before Benford tests. Extremely small values < 1 can be optionally dropped (--minval 1e-6).
- Tight-bounded/boolean/id-like columns (ports, flags, header lengths) are skipped by default.
- Timestamps: if not parseable, use --no-window to run dataset-wide.
"""

import argparse
import os
import math
import warnings
from typing import Dict, Tuple, List, Optional
import numpy as np
import pandas as pd

# ---------- Benford helpers ----------

def expected_fd() -> np.ndarray:
    """Expected first-digit (1..9) probabilities per Benford."""
    return np.array([math.log10(1 + 1/d) for d in range(1,10)])

def expected_ftd() -> np.ndarray:
    """Expected first-two-digit (10..99) probabilities per Benford."""
    return np.array([math.log10(1 + 1/d) for d in range(10,100)])

def first_digit(arr: np.ndarray) -> np.ndarray:
    """Extract first digit of positive numbers (>= small epsilon). Zeros/negatives are filtered out earlier."""
    if arr.size == 0:
        return np.array([], dtype=int)
    with np.errstate(divide='ignore', invalid='ignore'):
        mags = np.floor(np.log10(arr))
    # Handle edge cases where log10 might produce -inf or nan
    valid_mask = np.isfinite(mags)
    if not np.any(valid_mask):
        return np.array([], dtype=int)
    
    arr = arr[valid_mask]
    mags = mags[valid_mask]
    scaled = arr / (10 ** mags)
    fd = np.floor(scaled).astype(int)
    # Ensure digits are in valid range [1-9]
    fd = np.clip(fd, 1, 9)
    return fd

def first_two_digits(arr: np.ndarray) -> np.ndarray:
    """
    Extract first two digits of positive numbers >= 10.
    Numbers < 10 are filtered out since they don't have two significant digits.
    """
    if arr.size == 0:
        return np.array([], dtype=int)
    
    # Filter out values < 10 (can't have two significant digits)
    arr = arr[arr >= 10]
    
    if arr.size == 0:
        return np.array([], dtype=int)
    
    with np.errstate(divide='ignore', invalid='ignore'):
        mags = np.floor(np.log10(arr))
    
    valid_mask = np.isfinite(mags)
    if not np.any(valid_mask):
        return np.array([], dtype=int)
    
    arr = arr[valid_mask]
    mags = mags[valid_mask]
    
    # Shift to get first two digits
    scaled = arr / (10 ** (mags - 1))
    ftd = np.floor(scaled).astype(int)
    ftd = np.clip(ftd, 10, 99)
    return ftd

def js_distance(p: np.ndarray, q: np.ndarray, eps: float = 1e-12) -> float:
    """Jensen-Shannon distance between two distributions."""
    # Ensure inputs are valid probabilities
    if p.size != q.size:
        raise ValueError("Probability arrays must have same length")
    
    p = np.clip(p, eps, 1.0)
    q = np.clip(q, eps, 1.0)
    p = p / p.sum()
    q = q / q.sum()
    
    m = 0.5 * (p + q)
    
    with np.errstate(divide='ignore', invalid='ignore'):
        kl_pm = np.sum(p * np.log2(p / m))
        kl_qm = np.sum(q * np.log2(q / m))
    
    jsd = 0.5 * (kl_pm + kl_qm)
    
    # JSD should be non-negative, but numerical errors might produce small negative values
    jsd = max(0, jsd)
    
    return float(math.sqrt(jsd))

def mad_stat(p_obs: np.ndarray, p_exp: np.ndarray) -> float:
    """Mean absolute deviation between observed and expected probabilities."""
    return float(np.mean(np.abs(p_obs - p_exp)))

def chi_square_stat(counts: np.ndarray, p_exp: np.ndarray) -> float:
    """
    Pearson chi-square statistic.
    Note: For Benford's Law, critical values are:
    - α=0.05 (95% confidence): χ² ≈ 15.51 for 8 degrees of freedom (first digit)
    - α=0.05 (95% confidence): χ² ≈ 113.14 for 89 degrees of freedom (first two digits)
    """
    n = counts.sum()
    if n == 0:
        return np.nan
    
    exp_counts = p_exp * n
    
    # Avoid division by zero
    valid_mask = exp_counts > 0
    if not np.any(valid_mask):
        return np.nan
    
    chi2 = np.sum((counts[valid_mask] - exp_counts[valid_mask])**2 / exp_counts[valid_mask])
    return float(chi2)

def benford_test(values: np.ndarray, two_digit: bool=False, min_samples: int=30) -> Dict[str, float]:
    """
    Compute observed distribution and scores vs Benford expectations.
    
    Args:
        values: Array of numerical values to test
        two_digit: If True, test first two digits; otherwise test first digit
        min_samples: Minimum sample size required for testing (default 30)
    
    Returns:
        Dictionary with keys: n, mad, chi2, jsd
    """
    values = values[np.isfinite(values)]
    values = values[values > 0]
    
    if values.size < min_samples:
        return {"n": int(values.size), "mad": np.nan, "chi2": np.nan, "jsd": np.nan}
    
    if two_digit:
        digits = first_two_digits(values)
        if digits.size < min_samples:
            return {"n": int(digits.size), "mad": np.nan, "chi2": np.nan, "jsd": np.nan}
        domain = np.arange(10, 100)
        p_exp = expected_ftd()
    else:
        digits = first_digit(values)
        if digits.size < min_samples:
            return {"n": int(digits.size), "mad": np.nan, "chi2": np.nan, "jsd": np.nan}
        domain = np.arange(1, 10)
        p_exp = expected_fd()

    counts = np.array([np.sum(digits == d) for d in domain], dtype=float)
    n = counts.sum()
    
    if n == 0:
        return {"n": 0, "mad": np.nan, "chi2": np.nan, "jsd": np.nan}

    p_obs = counts / n
    
    try:
        mad = mad_stat(p_obs, p_exp)
        chi2 = chi_square_stat(counts, p_exp)
        jsd = js_distance(p_obs, p_exp)
    except Exception as e:
        warnings.warn(f"Error computing statistics: {e}")
        return {"n": int(n), "mad": np.nan, "chi2": np.nan, "jsd": np.nan}
    
    return {"n": int(n), "mad": mad, "chi2": chi2, "jsd": jsd}

# ---------- Column heuristics ----------

DEFAULT_INCLUDE_HINTS = [
    "bytes", "packets", "duration", "iat", "size", "length", "rate", "throughput",
    "window", "active", "idle", "variance", "std", "mean", "total"
]
DEFAULT_EXCLUDE_HINTS = [
    "ip", "port", "protocol", "flag", "header", "flow id", "label", "cwe", "ece",
    "min_seg_size", "ack", "syn", "urg", "psh", "rst", "fin", "count", "ratio"
]

def pick_candidate_columns(df: pd.DataFrame, include_hints=None, exclude_hints=None) -> List[str]:
    """
    Auto-select columns likely to follow Benford's Law based on naming heuristics.
    """
    include_hints = include_hints or DEFAULT_INCLUDE_HINTS
    exclude_hints = exclude_hints or DEFAULT_EXCLUDE_HINTS
    num_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    picks = []
    
    for c in num_cols:
        cl = c.lower().strip()
        
        # Exclude certain patterns
        if any(h in cl for h in exclude_hints):
            continue
        
        # Include if matches hints
        if any(h in cl for h in include_hints):
            picks.append(c)
    
    # Remove duplicates while preserving order
    seen = set()
    result = []
    for c in picks:
        if c not in seen:
            result.append(c)
            seen.add(c)
    
    return result

# ---------- Main routine ----------

def analyze_frame(df: pd.DataFrame,
                  cols: List[str],
                  two_digit: bool,
                  minval: float,
                  group_key: Optional[str]=None,
                  time_col: Optional[str]=None,
                  window: Optional[str]=None) -> pd.DataFrame:
    """
    Analyze Benford's Law conformity for specified columns.
    
    Args:
        df: Input DataFrame
        cols: List of columns to analyze
        two_digit: Whether to also compute two-digit tests
        minval: Minimum value threshold
        group_key: Column name to group by (e.g., 'Source IP')
        time_col: Timestamp column name
        window: Time window size (e.g., '15min')
    """
    # Validate columns exist
    missing_cols = [c for c in cols if c not in df.columns]
    if missing_cols:
        warnings.warn(f"Columns not found in dataframe: {missing_cols}")
        cols = [c for c in cols if c in df.columns]
    
    if not cols:
        raise ValueError("No valid columns to analyze")
    
    if time_col and window:
        df = df.copy()
        df[time_col] = pd.to_datetime(df[time_col], errors="coerce")
        df = df.dropna(subset=[time_col])
        
        if df.empty:
            warnings.warn("No valid timestamps found after parsing")
            return pd.DataFrame()
        
        df = df.set_index(time_col)
        
        # Group by time window and optionally by entity
        if group_key:
            grouper = [pd.Grouper(freq=window), group_key]
        else:
            grouper = [pd.Grouper(freq=window)]
        
        g = df.groupby(grouper)
    else:
        # Group only by entity or create single group
        if group_key:
            g = df.groupby(group_key)
        else:
            df = df.copy()
            df["_group_dummy"] = "ALL"
            g = df.groupby("_group_dummy")

    records = []
    
    for gkey, sub in g:
        if sub.empty:
            continue
        
        # Parse group key components
        time_window = None
        entity = None
        
        if isinstance(gkey, tuple):
            # Multiple grouping keys
            for k in gkey:
                if isinstance(k, pd.Timestamp):
                    time_window = k
                else:
                    entity = k
        else:
            # Single grouping key
            if isinstance(gkey, pd.Timestamp):
                time_window = gkey
            elif gkey == "ALL":
                entity = "ALL"
            else:
                entity = gkey

        for c in cols:
            vals = pd.to_numeric(sub[c], errors="coerce").values
            vals = vals[np.isfinite(vals)]
            vals = np.abs(vals) # use convert negative into positive
            vals = vals[vals > 0]
            
            if minval is not None and minval > 0:
                vals = vals[vals >= minval]
            
            stats1 = benford_test(vals, two_digit=False)
            stats2 = benford_test(vals, two_digit=True) if two_digit else {
                "n": np.nan, "mad": np.nan, "chi2": np.nan, "jsd": np.nan
            }
            
            rec = {
                "time_window_start": time_window.isoformat() if isinstance(time_window, pd.Timestamp) else None,
                "entity": str(entity) if entity is not None else None,
                "column": c,
                "n_1d": stats1["n"],
                "mad_1d": stats1["mad"],
                "chi2_1d": stats1["chi2"],
                "jsd_1d": stats1["jsd"],
                "n_2d": stats2["n"],
                "mad_2d": stats2["mad"],
                "chi2_2d": stats2["chi2"],
                "jsd_2d": stats2["jsd"],
            }
            records.append(rec)
    
    return pd.DataFrame.from_records(records)

def add_severity(df_scores: pd.DataFrame, mad_field: str="mad_1d") -> pd.DataFrame:
    """
    Add severity classification based on MAD thresholds.
    
    Thresholds (Nigrini, 2012):
    - MAD < 0.006: Close conformity
    - MAD 0.006-0.012: Acceptable conformity
    - MAD 0.012-0.015: Marginally acceptable conformity
    - MAD > 0.015: Nonconformity (potential anomaly)
    """
    def bucket(m):
        if pd.isna(m):
            return "insufficient"
        if m < 0.006:
            return "close"
        if m < 0.012:
            return "acceptable"
        if m < 0.015:
            return "marginal"
        return "nonconformity"
    
    df_scores = df_scores.copy()
    df_scores["severity"] = df_scores[mad_field].apply(bucket)
    return df_scores

def main():
    ap = argparse.ArgumentParser(
        description="Benford's Law anomaly detector for network flow data",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    ap.add_argument("--csv", nargs="+", required=True, 
                    help="One or more CSV file paths")
    ap.add_argument("--time-col", default=None, 
                    help="Timestamp column name (parseable by pandas)")
    ap.add_argument("--entity-col", default=None, 
                    help="Entity column to group by (e.g., 'Source IP' or 'Destination IP')")
    ap.add_argument("--cols", nargs="*", default=None, 
                    help="Specific numeric columns to analyze; if omitted, auto-select likely ones")
    ap.add_argument("--window", default=None, 
                    help="Sliding window size, e.g., '5min', '15min', '1H'. Omit to analyze all together.")
    ap.add_argument("--minval", type=float, default=1e-9, 
                    help="Drop values below this before Benford tests (default 1e-9)")
    ap.add_argument("--min-samples", type=int, default=30,
                    help="Minimum sample size for Benford test (default 30)")
    ap.add_argument("--outdir", default="benford_out", 
                    help="Output directory")
    ap.add_argument("--save-plots", action="store_true", 
                    help="Save bar plots of observed vs expected distributions per (column, group, window)")
    args = ap.parse_args()

    os.makedirs(args.outdir, exist_ok=True)

    # Load CSV files
    dfs = []
    for p in args.csv:
        print(f"Loading {p}...")
        try:
            df_temp = pd.read_csv(p, low_memory=False)
        except Exception as e:
            print(f"  Trying with auto-delimiter detection...")
            try:
                df_temp = pd.read_csv(p, sep=None, engine="python", low_memory=False)
            except Exception as e2:
                print(f"  ERROR loading {p}: {e2}")
                continue
        
        # Check for duplicate columns
        if df_temp.columns.duplicated().any():
            dup_cols = df_temp.columns[df_temp.columns.duplicated()].tolist()
            warnings.warn(f"Duplicate columns found in {p}: {dup_cols}. Renaming...")
            df_temp = df_temp.loc[:, ~df_temp.columns.duplicated(keep='first')]
        
        dfs.append(df_temp)
        print(f"  Loaded {len(df_temp)} rows, {len(df_temp.columns)} columns")
    
    if not dfs:
        raise SystemExit("No CSV files successfully loaded")
    
    df = pd.concat(dfs, ignore_index=True)
    print(f"\nCombined dataset: {len(df)} rows, {len(df.columns)} columns")

    # Select columns to analyze
    if args.cols and len(args.cols) > 0:
        cols = args.cols
        print(f"Using user-specified columns: {cols}")
    else:
        cols = pick_candidate_columns(df)
        if not cols:
            # Fallback to common CIC-IDS column names
            fallback = [
                "Flow Bytes/s", "Flow Packets/s",
                "Total Length of Fwd Packets", "Total Length of Bwd Packets",
                "Fwd Packet Length Mean", "Bwd Packet Length Mean",
                "Packet Length Mean", "Packet Length Std",
                "Flow Duration", "Flow IAT Mean", "Flow IAT Std",
                "Active Mean", "Idle Mean", "Fwd IAT Mean", "Bwd IAT Mean"
            ]
            cols = [c for c in fallback if c in df.columns]
        print(f"Auto-selected {len(cols)} columns: {cols[:5]}{'...' if len(cols) > 5 else ''}")
    
    if not cols:
        raise SystemExit("No numeric columns found to analyze. Provide --cols.")

    # Run Benford analysis
    print(f"\nAnalyzing Benford's Law conformity...")
    scores = analyze_frame(
        df=df,
        cols=cols,
        two_digit=True,
        minval=args.minval,
        group_key=args.entity_col,
        time_col=args.time_col,
        window=args.window
    )

    if scores.empty:
        print("WARNING: No results generated. Check your data and parameters.")
        return

    # Add severity classification
    scores = add_severity(scores, "mad_1d")
    
    # Save results
    out_csv = os.path.join(args.outdir, "benford_scores.csv")
    scores.to_csv(out_csv, index=False)

    # Generate alerts (high deviation + sufficient samples)
    alerts = scores[(scores["severity"] == "nonconformity") & (scores["n_1d"] >= 200)]
    alerts_csv = os.path.join(args.outdir, "alerts.csv")
    alerts.to_csv(alerts_csv, index=False)

    print(f"\nWrote scores: {out_csv}")
    print(f"Wrote alerts: {alerts_csv}")
    print(f"\nSeverity distribution:")
    print(scores["severity"].value_counts())
    
    print(f"\nTop 10 potential anomalies (by JSD and MAD):")
    if not alerts.empty:
        top_alerts = alerts.sort_values(["jsd_1d", "mad_1d"], ascending=False).head(10)
        print(top_alerts[["column", "entity", "n_1d", "mad_1d", "chi2_1d", "jsd_1d"]].to_string(index=False))
    else:
        print("(none under current thresholds)")

    # Generate plots if requested
    if args.save_plots and (args.entity_col is None) and (args.window is None):
        try:
            import matplotlib.pyplot as plt
        except ImportError:
            print("\nWARNING: matplotlib not available, skipping plots")
            return

        def plot_dist(values: np.ndarray, title: str, outpath: str):
            values = values[np.isfinite(values)]
            values = values[values > 0]
            if values.size < 30:
                return
            
            fd = first_digit(values)
            if fd.size == 0:
                return
            
            counts = np.array([np.sum(fd == d) for d in range(1,10)], dtype=float)
            if counts.sum() == 0:
                return
            
            p_obs = counts / counts.sum()
            p_exp = expected_fd()

            fig, ax = plt.subplots(figsize=(8, 5))
            x = np.arange(1, 10)
            width = 0.35
            ax.bar(x - width/2, p_obs, width, label="Observed", alpha=0.8)
            ax.bar(x + width/2, p_exp, width, label="Expected (Benford)", alpha=0.8)
            ax.set_title(title)
            ax.set_xlabel("First digit")
            ax.set_ylabel("Probability")
            ax.set_xticks(x)
            ax.legend()
            ax.grid(axis='y', alpha=0.3)
            fig.savefig(outpath, bbox_inches="tight", dpi=100)
            plt.close(fig)
            print(f"  Saved plot: {outpath}")

        print(f"\nGenerating plots...")
        for c in cols:
            vals = pd.to_numeric(df[c], errors="coerce").values
            import re
            safe = re.sub(r'[^A-Za-z0-9._-]+', '_', c)
            outp = os.path.join(args.outdir, f"benford_{safe}.png")
            plot_dist(vals, f"Benford first-digit: {c}", outp)

if __name__ == "__main__":
    main()

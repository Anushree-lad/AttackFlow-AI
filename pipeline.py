"""
pipeline.py
-----------
Core AttackFlow AI pipeline.

Six stages:

  1. Load
       Read raw network events.

  2. Preprocess
       Feature engineering and behavioral features.

  3. Detect
       Unsupervised anomaly detection using Isolation Forest.

  4. Correlate
       Group anomalous events by shared entity and time window.

  5. Reconstruct
       Classify attack stages and identify attack patterns.

  6. Score
       Calculate risk score and progression likelihood.

Attack pattern identification is rule-based.

Isolation Forest:
    Finds unusual behavior.

Attack Evidence Engine:
    Explains which supported security behavior patterns
    match the anomalous activity.

Important:
    A small anomalous cluster is NOT automatically treated
    as a complete attack sequence.

    1-2 events -> Isolated Anomaly
    3+ events  -> Attack Sequence

Run:
    python pipeline.py

Output:
    output/sequences.json
"""

import json
from collections import defaultdict

import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

from attack_evidence import analyze_attack_evidence


# ===========================================================================
# Configuration
# ===========================================================================

EVENTS_PATH = "data/events.csv"
OUT_PATH = "output/sequences.json"

CORRELATION_WINDOW_MINUTES = 20

ANOMALY_CONTAMINATION = 0.06

MIN_ATTACK_SEQUENCE_EVENTS = 3


# ===========================================================================
# Stage 2: Preprocessing / Feature Extraction
# ===========================================================================

def preprocess(df: pd.DataFrame):
    """
    Convert raw events into numerical behavioral features.

    Rolling features only use previous events.
    This prevents future-data leakage.
    """

    required_columns = [
        "timestamp",
        "src_ip",
        "dst_ip",
        "dst_port",
        "protocol",
        "bytes_sent",
        "bytes_received",
        "duration_ms",
        "failed_logins",
    ]

    missing = [
        column
        for column in required_columns
        if column not in df.columns
    ]

    if missing:
        raise ValueError(
            f"Missing required columns in events.csv: {missing}"
        )

    df = df.copy()

    # -----------------------------------------------------------------------
    # Timestamp
    # -----------------------------------------------------------------------

    df["timestamp"] = pd.to_datetime(
        df["timestamp"],
        errors="coerce"
    )

    if df["timestamp"].isna().any():
        bad_rows = int(df["timestamp"].isna().sum())

        raise ValueError(
            f"{bad_rows} invalid timestamp value(s) found."
        )

    # -----------------------------------------------------------------------
    # Sort chronologically
    # -----------------------------------------------------------------------

    df = (
        df.sort_values("timestamp")
        .reset_index(drop=True)
    )

    # -----------------------------------------------------------------------
    # Numeric fields
    # -----------------------------------------------------------------------

    numeric_columns = [
        "dst_port",
        "bytes_sent",
        "bytes_received",
        "duration_ms",
        "failed_logins",
    ]

    for column in numeric_columns:

        df[column] = pd.to_numeric(
            df[column],
            errors="coerce"
        ).fillna(0)

    # -----------------------------------------------------------------------
    # Protocol encoding
    # -----------------------------------------------------------------------

    df["protocol_enc"] = (
        df["protocol"]
        .astype(str)
        .str.upper()
        .map({
            "TCP": 0,
            "UDP": 1
        })
        .fillna(2)
    )

    # -----------------------------------------------------------------------
    # Hour of event
    # -----------------------------------------------------------------------

    df["hour"] = (
        df["timestamp"].dt.hour
    )

    # -----------------------------------------------------------------------
    # Rolling behavioral features
    # -----------------------------------------------------------------------

    df["unique_dst_ports_5m"] = 0
    df["event_count_5m"] = 0

    window = pd.Timedelta(
        minutes=5
    )

    by_src = defaultdict(list)

    unique_ports_col = []
    count_col = []

    for _, row in df.iterrows():

        src = str(row["src_ip"])
        timestamp = row["timestamp"]

        history = by_src[src]

        # Keep only events in the previous 5 minutes.
        history[:] = [
            (old_timestamp, old_port)
            for old_timestamp, old_port in history
            if timestamp - old_timestamp <= window
        ]

        # Calculate features BEFORE adding current event.
        unique_ports_col.append(
            len({
                old_port
                for _, old_port in history
            })
        )

        count_col.append(
            len(history)
        )

        # Add current event for future rows.
        history.append(
            (
                timestamp,
                int(row["dst_port"])
            )
        )

    df["unique_dst_ports_5m"] = (
        unique_ports_col
    )

    df["event_count_5m"] = (
        count_col
    )

    # -----------------------------------------------------------------------
    # Features used by Isolation Forest
    # -----------------------------------------------------------------------

    feature_cols = [
        "bytes_sent",
        "bytes_received",
        "duration_ms",
        "dst_port",
        "protocol_enc",
        "failed_logins",
        "unique_dst_ports_5m",
        "event_count_5m",
    ]

    return df, feature_cols


# ===========================================================================
# Stage 3: Anomaly Detection
# ===========================================================================

def detect_anomalies(
    df: pd.DataFrame,
    feature_cols
) -> pd.DataFrame:
    """
    Detect unusual events using Isolation Forest.
    """

    df = df.copy()

    X = df[feature_cols].copy()

    # Make sure numerical values are valid.
    X = X.apply(
        pd.to_numeric,
        errors="coerce"
    ).fillna(0)

    # -----------------------------------------------------------------------
    # Standardize features
    # -----------------------------------------------------------------------

    scaler = StandardScaler()

    X_scaled = scaler.fit_transform(
        X
    )

    # -----------------------------------------------------------------------
    # Isolation Forest
    # -----------------------------------------------------------------------

    model = IsolationForest(
        n_estimators=200,
        contamination=ANOMALY_CONTAMINATION,
        random_state=42,
    )

    model.fit(
        X_scaled
    )

    # -----------------------------------------------------------------------
    # Raw anomaly score
    # -----------------------------------------------------------------------

    raw_scores = model.decision_function(
        X_scaled
    )

    score_min = raw_scores.min()
    score_max = raw_scores.max()

    if score_max == score_min:

        df["anomaly_score"] = 0.0

    else:

        df["anomaly_score"] = (
            1
            - (
                (raw_scores - score_min)
                / (
                    score_max - score_min
                )
            )
        )

    # -----------------------------------------------------------------------
    # Predictions
    # -----------------------------------------------------------------------

    predictions = model.predict(
        X_scaled
    )

    # -1 = anomaly
    #  1 = normal

    df["is_anomalous"] = (
        predictions == -1
    )

    return df


# ===========================================================================
# Stage 4: Event Correlation
# ===========================================================================

def correlate_events(
    df: pd.DataFrame
):
    """
    Group anomalous events when they:

        1. share an entity
        2. occur within the configured time window

    Entity:
        source IP or destination IP
    """

    anomalous = (
        df[df["is_anomalous"]]
        .sort_values("timestamp")
        .reset_index(drop=True)
    )

    if anomalous.empty:
        return []

    # -----------------------------------------------------------------------
    # Union-Find structure
    # -----------------------------------------------------------------------

    parent = list(
        range(len(anomalous))
    )

    def find(index):

        while parent[index] != index:

            parent[index] = parent[
                parent[index]
            ]

            index = parent[index]

        return index

    def union(index_a, index_b):

        root_a = find(index_a)
        root_b = find(index_b)

        if root_a != root_b:
            parent[root_a] = root_b

    # -----------------------------------------------------------------------
    # Correlation window
    # -----------------------------------------------------------------------

    window = pd.Timedelta(
        minutes=CORRELATION_WINDOW_MINUTES
    )

    entity_last_seen = {}

    for index, row in anomalous.iterrows():

        entities = {
            str(row["src_ip"]),
            str(row["dst_ip"]),
        }

        for entity in entities:

            if entity in entity_last_seen:

                previous_index, previous_timestamp = (
                    entity_last_seen[entity]
                )

                if (
                    row["timestamp"]
                    - previous_timestamp
                    <= window
                ):

                    union(
                        index,
                        previous_index
                    )

            entity_last_seen[entity] = (
                index,
                row["timestamp"]
            )

    # -----------------------------------------------------------------------
    # Build clusters
    # -----------------------------------------------------------------------

    clusters = defaultdict(list)

    for index in range(
        len(anomalous)
    ):

        root = find(index)

        clusters[root].append(
            index
        )

    result = []

    for indices in clusters.values():

        cluster = (
            anomalous
            .iloc[indices]
            .copy()
            .sort_values("timestamp")
        )

        result.append(
            cluster
        )

    # Largest clusters first
    result.sort(
        key=len,
        reverse=True
    )

    return result


# ===========================================================================
# Stage 5A: Attack Stage Classification
# ===========================================================================

def classify_stage(
    row
) -> str:
    """
    Map one event to an attack lifecycle stage.

    Order:

        1. Reconnaissance
        2. Lateral Movement
        3. Exfiltration
        4. Initial Access
        5. Suspicious Activity
    """

    protocol = str(
        row.get(
            "protocol",
            ""
        )
    ).upper()

    try:

        dst_port = int(
            row.get(
                "dst_port",
                0
            )
        )

    except (
        ValueError,
        TypeError
    ):

        dst_port = 0

    failed_logins = float(
        row.get(
            "failed_logins",
            0
        )
    )

    bytes_sent = float(
        row.get(
            "bytes_sent",
            0
        )
    )

    bytes_received = float(
        row.get(
            "bytes_received",
            0
        )
    )

    unique_ports = float(
        row.get(
            "unique_dst_ports_5m",
            0
        )
    )

    event_count = float(
        row.get(
            "event_count_5m",
            0
        )
    )

    # -----------------------------------------------------------------------
    # Reconnaissance
    # -----------------------------------------------------------------------

    if unique_ports >= 5:
        return "Reconnaissance"

    recon_ports = {
        21,
        22,
        23,
        25,
        53,
        80,
        110,
        135,
        139,
        143,
        443,
        445,
        1433,
        3306,
        3389,
        5432,
        8080,
    }

    if (
        dst_port in recon_ports
        and event_count >= 4
    ):
        return "Reconnaissance"

    # -----------------------------------------------------------------------
    # Lateral Movement
    # -----------------------------------------------------------------------

    lateral_ports = {
        135,
        139,
        445,
        3389,
        5985,
        5986,
    }

    if dst_port in lateral_ports:
        return "Lateral Movement"

    if (
        bytes_received > 50000
        and event_count >= 3
    ):
        return "Lateral Movement"

    # -----------------------------------------------------------------------
    # Exfiltration
    # -----------------------------------------------------------------------

    if bytes_sent > 100000:
        return "Exfiltration"

    if (
        bytes_sent
        > bytes_received * 5
        and bytes_sent > 50000
    ):
        return "Exfiltration"

    # -----------------------------------------------------------------------
    # Initial Access
    # -----------------------------------------------------------------------

    if failed_logins >= 3:
        return "Initial Access"

    initial_access_ports = {
        22,
        23,
        80,
        443,
        8080,
    }

    if dst_port in initial_access_ports:
        return "Initial Access"

    # -----------------------------------------------------------------------
    # Suspicious Activity
    # -----------------------------------------------------------------------

    if (
        protocol not in {
            "TCP",
            "UDP",
        }
        or event_count >= 10
    ):
        return "Suspicious Activity"

    return "Suspicious Activity"


# ===========================================================================
# Stage 5B: Existing Rule-Based Attack Pattern Detection
# ===========================================================================

def identify_attack_patterns(
    cluster: pd.DataFrame
):
    """
    Identify specific security behaviors from a correlated
    cluster using transparent rule-based logic.

    Returns:
        patterns
        reasons
    """

    patterns = []
    reasons = []

    # -----------------------------------------------------------------------
    # Basic cluster information
    # -----------------------------------------------------------------------

    event_count = len(
        cluster
    )

    unique_sources = (
        cluster[
            "src_ip"
        ]
        .astype(str)
        .nunique()
    )

    unique_destinations = (
        cluster[
            "dst_ip"
        ]
        .astype(str)
        .nunique()
    )

    unique_ports = (
        cluster[
            "dst_port"
        ]
        .nunique()
    )

    total_bytes_sent = pd.to_numeric(
        cluster["bytes_sent"],
        errors="coerce"
    ).fillna(0).sum()

    total_bytes_received = pd.to_numeric(
        cluster["bytes_received"],
        errors="coerce"
    ).fillna(0).sum()

    max_failed_logins = pd.to_numeric(
        cluster["failed_logins"],
        errors="coerce"
    ).fillna(0).max()

    # -----------------------------------------------------------------------
    # Port Scanning
    # -----------------------------------------------------------------------

    if unique_ports >= 5:

        patterns.append(
            "Port Scanning / Network Reconnaissance"
        )

        reasons.append(
            f"Source contacted {unique_ports} "
            f"distinct destination ports."
        )

    # -----------------------------------------------------------------------
    # SSH Brute Force / Access Attempt
    # -----------------------------------------------------------------------

    ssh_events = cluster[
        pd.to_numeric(
            cluster["dst_port"],
            errors="coerce"
        ) == 22
    ]

    ssh_failed_logins = pd.to_numeric(
        ssh_events["failed_logins"],
        errors="coerce"
    ).fillna(0).sum()

    if (
        len(ssh_events) >= 3
        and ssh_failed_logins >= 3
    ):

        patterns.append(
            "SSH Brute Force / Access Attempt"
        )

        reasons.append(
            f"{len(ssh_events)} SSH events with "
            f"{int(ssh_failed_logins)} failed login attempts."
        )

    elif len(ssh_events) >= 3:

        patterns.append(
            "Repeated SSH Access Attempts"
        )

        reasons.append(
            f"{len(ssh_events)} SSH connection attempts "
            f"were observed."
        )

    # -----------------------------------------------------------------------
    # Lateral Movement
    # -----------------------------------------------------------------------

    lateral_ports = {
        135,
        139,
        445,
        3389,
        5985,
        5986,
    }

    lateral_events = cluster[
        pd.to_numeric(
            cluster["dst_port"],
            errors="coerce"
        ).isin(
            lateral_ports
        )
    ]

    lateral_destinations = (
        lateral_events[
            "dst_ip"
        ]
        .astype(str)
        .nunique()
    )

    if len(lateral_events) >= 2:

        patterns.append(
            "SMB/RDP/Windows Lateral Movement"
        )

        reasons.append(
            f"{len(lateral_events)} events used "
            f"Windows remote-service ports across "
            f"{lateral_destinations} destination host(s)."
        )

    # -----------------------------------------------------------------------
    # Possible Data Exfiltration
    # -----------------------------------------------------------------------

    if total_bytes_sent > 100000:

        patterns.append(
            "Possible Data Exfiltration"
        )

        reasons.append(
            f"Total outbound data reached "
            f"{total_bytes_sent:.0f} bytes."
        )

    elif (
        total_bytes_sent > 50000
        and total_bytes_received > 0
        and total_bytes_sent
        > total_bytes_received * 5
    ):

        patterns.append(
            "Possible Data Exfiltration"
        )

        reasons.append(
            "Outbound traffic was substantially "
            "larger than inbound traffic."
        )

    # -----------------------------------------------------------------------
    # Multi-host communication
    # -----------------------------------------------------------------------

    if (
        unique_sources >= 1
        and unique_destinations >= 4
        and event_count >= 5
    ):

        if (
            "Port Scanning / Network Reconnaissance"
            not in patterns
        ):

            patterns.append(
                "Multi-Host Network Reconnaissance"
            )

            reasons.append(
                f"Activity involved "
                f"{unique_destinations} "
                f"destination hosts."
            )

    # -----------------------------------------------------------------------
    # Repeated authentication failures
    # -----------------------------------------------------------------------

    if (
        max_failed_logins >= 3
        and
        "SSH Brute Force / Access Attempt"
        not in patterns
    ):

        patterns.append(
            "Repeated Authentication Failures"
        )

        reasons.append(
            f"Maximum failed-login count reached "
            f"{int(max_failed_logins)}."
        )

    # -----------------------------------------------------------------------
    # Multi-stage attack
    # -----------------------------------------------------------------------

    stage_set = set(
        cluster[
            "stage"
        ].astype(str)
    )

    meaningful_stages = {
        "Reconnaissance",
        "Initial Access",
        "Lateral Movement",
        "Exfiltration",
    }

    stage_count = len(
        stage_set.intersection(
            meaningful_stages
        )
    )

    if stage_count >= 3:

        patterns.append(
            "Multi-Stage Network Attack"
        )

        reasons.append(
            f"Correlated activity progressed through "
            f"{stage_count} attack lifecycle stages."
        )

    # -----------------------------------------------------------------------
    # Fallback
    # -----------------------------------------------------------------------

    if not patterns:

        patterns.append(
            "Suspicious / Unknown Activity"
        )

        reasons.append(
            f"{event_count} anomalous event(s) were "
            f"correlated, but no specific attack pattern "
            f"matched the available evidence."
        )

    # Remove duplicates while preserving order.
    patterns = list(
        dict.fromkeys(
            patterns
        )
    )

    reasons = list(
        dict.fromkeys(
            reasons
        )
    )

    return (
        patterns,
        reasons
    )


# ===========================================================================
# Stage 5C: Attack Sequence Reconstruction
# ===========================================================================

def reconstruct_sequence(
    cluster: pd.DataFrame,
    sequence_id: int
) -> dict:
    """
    Reconstruct one correlated cluster.

    Small clusters:
        Isolated Anomaly

    3+ correlated events:
        Attack Sequence
    """

    cluster = (
        cluster
        .sort_values("timestamp")
        .copy()
    )

    # -----------------------------------------------------------------------
    # Classify every event
    # -----------------------------------------------------------------------

    cluster["stage"] = cluster.apply(
        classify_stage,
        axis=1
    )

    # -----------------------------------------------------------------------
    # Preserve order in which stages appeared
    # -----------------------------------------------------------------------

    stages_observed = []

    for stage in cluster["stage"]:

        if stage not in stages_observed:

            stages_observed.append(
                stage
            )

    # -----------------------------------------------------------------------
    # Existing rule-based patterns
    # -----------------------------------------------------------------------

    attack_patterns, detection_reasons = (
        identify_attack_patterns(
            cluster
        )
    )

    # -----------------------------------------------------------------------
    # NEW: Attack Evidence Engine
    # -----------------------------------------------------------------------

    evidence_result = analyze_attack_evidence(
        cluster
    )

    # -----------------------------------------------------------------------
    # Determine activity type
    # -----------------------------------------------------------------------

    event_count = len(
        cluster
    )

    if (
        event_count
        < MIN_ATTACK_SEQUENCE_EVENTS
    ):

        sequence_type = (
            "Isolated Anomaly"
        )

    else:

        sequence_type = (
            "Attack Sequence"
        )

    # -----------------------------------------------------------------------
    # Collect entities
    # -----------------------------------------------------------------------

    entities = set()

    for _, row in cluster.iterrows():

        entities.add(
            str(row["src_ip"])
        )

        entities.add(
            str(row["dst_ip"])
        )

    # -----------------------------------------------------------------------
    # Average anomaly confidence
    # -----------------------------------------------------------------------

    avg_anomaly_score = float(
        cluster[
            "anomaly_score"
        ].mean()
    )

    # -----------------------------------------------------------------------
    # Ground truth
    # -----------------------------------------------------------------------

    ground_truth = None

    if "true_campaign" in cluster.columns:

        campaigns = (
            cluster[
                "true_campaign"
            ]
            .dropna()
            .unique()
        )

        if len(campaigns) > 0:

            ground_truth = str(
                campaigns[0]
            )

    # -----------------------------------------------------------------------
    # Timeline
    # -----------------------------------------------------------------------

    timeline = []

    for _, row in cluster.iterrows():

        timeline.append({
            "timestamp": row[
                "timestamp"
            ].isoformat(),

            "src_ip": str(
                row["src_ip"]
            ),

            "dst_ip": str(
                row["dst_ip"]
            ),

            "dst_port": int(
                row["dst_port"]
            ),

            "stage": str(
                row["stage"]
            ),
        })

    # -----------------------------------------------------------------------
    # Final reconstructed sequence
    # -----------------------------------------------------------------------

    return {

        "sequence_id":
            f"seq_{sequence_id:03d}",

        "sequence_type":
            sequence_type,

        "start_time":
            cluster[
                "timestamp"
            ]
            .min()
            .isoformat(),

        "end_time":
            cluster[
                "timestamp"
            ]
            .max()
            .isoformat(),

        "event_count":
            event_count,

        "entities_involved":
            sorted(
                entities
            ),

        "stages_observed":
            stages_observed,

        # Existing rule-based attack information
        "attack_patterns":
            attack_patterns,

        "detection_reasons":
            detection_reasons,

        # NEW Attack Evidence Engine information
        "attack_types":
            evidence_result[
                "attack_types"
            ],

        "attack_evidence":
            evidence_result[
                "evidence"
            ],

        "attack_confidence":
            evidence_result[
                "confidence"
            ],

        "avg_anomaly_score":
            round(
                avg_anomaly_score,
                4
            ),

        "_ground_truth_campaign":
            ground_truth,

        "timeline":
            timeline,
    }


# ===========================================================================
# Stage 6: Risk Scoring
# ===========================================================================

STAGE_SEVERITY = {
    "Reconnaissance": 1,
    "Initial Access": 2,
    "Lateral Movement": 3,
    "Exfiltration": 4,
    "Suspicious Activity": 1,
}


STAGE_ORDER = [
    "Reconnaissance",
    "Initial Access",
    "Lateral Movement",
    "Exfiltration",
]


def score_risk(
    sequence: dict
) -> dict:
    """
    Calculate risk score and progression likelihood.

    Isolated anomalies receive a lower risk ceiling.
    Attack sequences use severity, breadth, confidence,
    event count and progression.
    """

    stages = sequence[
        "stages_observed"
    ]

    event_count = sequence[
        "event_count"
    ]

    sequence_type = sequence[
        "sequence_type"
    ]

    # -----------------------------------------------------------------------
    # Highest stage severity
    # -----------------------------------------------------------------------

    max_severity = max(
        (
            STAGE_SEVERITY.get(
                stage,
                1
            )
            for stage in stages
        ),
        default=1
    )

    # -----------------------------------------------------------------------
    # Entity breadth
    # -----------------------------------------------------------------------

    breadth_factor = min(
        len(
            sequence[
                "entities_involved"
            ]
        ) / 5,
        1.0
    )

    # -----------------------------------------------------------------------
    # Anomaly confidence
    # -----------------------------------------------------------------------

    confidence_factor = (
        sequence[
            "avg_anomaly_score"
        ]
    )

    # -----------------------------------------------------------------------
    # Isolated anomaly
    # -----------------------------------------------------------------------

    if (
        sequence_type
        == "Isolated Anomaly"
    ):

        risk_score = (
            10
            + confidence_factor * 20
            + min(
                breadth_factor * 10,
                10
            )
        )

        risk_score = round(
            min(
                risk_score,
                40
            ),
            1
        )

    else:

        # -------------------------------------------------------------------
        # Attack sequence
        # -------------------------------------------------------------------

        event_factor = min(
            event_count / 20,
            1.0
        )

        progression_factor = (
            len(
                [
                    stage
                    for stage in stages
                    if stage in STAGE_ORDER
                ]
            )
            / len(STAGE_ORDER)
        )

        risk_score = (
            (max_severity / 4) * 40
            + breadth_factor * 15
            + confidence_factor * 20
            + event_factor * 10
            + progression_factor * 15
        )

        risk_score = round(
            min(
                risk_score,
                100
            ),
            1
        )

    # -----------------------------------------------------------------------
    # Progression likelihood
    # -----------------------------------------------------------------------

    reached_indices = [
        STAGE_ORDER.index(stage)
        for stage in stages
        if stage in STAGE_ORDER
    ]

    if (
        sequence_type
        == "Isolated Anomaly"
    ):

        progression_likelihood = (
            "low — isolated anomaly; "
            "insufficient evidence for an attack sequence"
        )

    elif not reached_indices:

        progression_likelihood = (
            "low — suspicious activity only"
        )

    else:

        furthest = max(
            reached_indices
        )

        if furthest >= 3:

            progression_likelihood = (
                "high — exfiltration observed"
            )

        elif furthest == 2:

            progression_likelihood = (
                "high — lateral movement observed"
            )

        elif furthest == 1:

            progression_likelihood = (
                "medium — initial access observed; "
                "lateral movement may follow"
            )

        else:

            progression_likelihood = (
                "low-medium — reconnaissance observed"
            )

    # -----------------------------------------------------------------------
    # Risk level
    # -----------------------------------------------------------------------

    if risk_score >= 70:

        level = "Critical"

    elif risk_score >= 45:

        level = "High"

    elif risk_score >= 25:

        level = "Medium"

    else:

        level = "Low"

    # -----------------------------------------------------------------------
    # Explanation
    # -----------------------------------------------------------------------

    if (
        sequence_type
        == "Isolated Anomaly"
    ):

        explanation = (
            f"{event_count} anomalous event(s) "
            f"involving "
            f"{len(sequence['entities_involved'])} "
            f"host(s). This activity does not contain "
            f"enough correlated events to be treated "
            f"as a complete attack sequence."
        )

    else:

        explanation = (
            f"{len(sequence['entities_involved'])} "
            f"host(s) involved across "
            f"{len(stages)} distinct stage(s) "
            f"({', '.join(stages)}) over "
            f"{event_count} correlated events, "
            f"with an average anomaly confidence "
            f"of "
            f"{sequence['avg_anomaly_score']:.2f}."
        )

    sequence[
        "risk_score"
    ] = risk_score

    sequence[
        "risk_level"
    ] = level

    sequence[
        "progression_likelihood"
    ] = progression_likelihood

    sequence[
        "explanation"
    ] = explanation

    return sequence


# ===========================================================================
# Main Pipeline
# ===========================================================================

def run():

    # -----------------------------------------------------------------------
    # Stage 1
    # -----------------------------------------------------------------------

    print(
        "[1/6] Loading events..."
    )

    try:

        df = pd.read_csv(
            EVENTS_PATH
        )

    except FileNotFoundError:

        print(
            f"ERROR: Could not find "
            f"{EVENTS_PATH}"
        )

        return

    print(
        f"      {len(df)} raw events loaded"
    )

    # -----------------------------------------------------------------------
    # Stage 2
    # -----------------------------------------------------------------------

    print(
        "[2/6] Preprocessing / "
        "feature extraction..."
    )

    try:

        df, feature_cols = preprocess(
            df
        )

    except ValueError as error:

        print(
            f"ERROR during preprocessing: "
            f"{error}"
        )

        return

    print(
        f"      {len(feature_cols)} "
        f"behavioral features created"
    )

    # -----------------------------------------------------------------------
    # Stage 3
    # -----------------------------------------------------------------------

    print(
        "[3/6] Running anomaly detection "
        "(Isolation Forest)..."
    )

    try:

        df = detect_anomalies(
            df,
            feature_cols
        )

    except Exception as error:

        print(
            f"ERROR during anomaly detection: "
            f"{error}"
        )

        return

    anomalous_count = int(
        df[
            "is_anomalous"
        ].sum()
    )

    anomaly_percentage = (
        df[
            "is_anomalous"
        ].mean()
        * 100
    )

    print(
        f"      {anomalous_count} events "
        f"flagged anomalous "
        f"({anomaly_percentage:.1f}% "
        f"of traffic)"
    )

    # -----------------------------------------------------------------------
    # Stage 4
    # -----------------------------------------------------------------------

    print(
        "[4/6] Correlating anomalous "
        "events into clusters..."
    )

    clusters = correlate_events(
        df
    )

    print(
        f"      {len(clusters)} "
        f"candidate clusters found"
    )

    # -----------------------------------------------------------------------
    # Stage 5
    # -----------------------------------------------------------------------

    print(
        "[5/6] Reconstructing "
        "attack sequences..."
    )

    sequences = []

    for index, cluster in enumerate(
        clusters
    ):

        sequence = reconstruct_sequence(
            cluster,
            index + 1
        )

        sequences.append(
            sequence
        )

    # -----------------------------------------------------------------------
    # Count sequence types
    # -----------------------------------------------------------------------

    attack_sequence_count = sum(
        1
        for sequence in sequences
        if (
            sequence[
                "sequence_type"
            ]
            == "Attack Sequence"
        )
    )

    isolated_count = sum(
        1
        for sequence in sequences
        if (
            sequence[
                "sequence_type"
            ]
            == "Isolated Anomaly"
        )
    )

    print(
        f"      {attack_sequence_count} "
        f"attack sequence(s)"
    )

    print(
        f"      {isolated_count} "
        f"isolated anomaly group(s)"
    )

    # -----------------------------------------------------------------------
    # Stage 6
    # -----------------------------------------------------------------------

    print(
        "[6/6] Scoring risk & "
        "progression likelihood..."
    )

    sequences = [
        score_risk(
            sequence
        )
        for sequence in sequences
    ]

    # Highest risk first.
    sequences.sort(
        key=lambda sequence: (
            sequence[
                "risk_score"
            ],
            sequence[
                "event_count"
            ]
        ),
        reverse=True
    )

    # -----------------------------------------------------------------------
    # Ensure output directory exists
    # -----------------------------------------------------------------------

    import os

    os.makedirs(
        os.path.dirname(
            OUT_PATH
        ),
        exist_ok=True
    )

    # -----------------------------------------------------------------------
    # Save JSON
    # -----------------------------------------------------------------------

    with open(
        OUT_PATH,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            sequences,
            file,
            indent=2
        )

    print(
        f"\nDone. {len(sequences)} "
        f"correlated result(s) written "
        f"-> {OUT_PATH}"
    )

    # -----------------------------------------------------------------------
    # No detections
    # -----------------------------------------------------------------------

    if not sequences:

        print(
            "No anomalous activity detected."
        )

        return

    # -----------------------------------------------------------------------
    # Summary
    # -----------------------------------------------------------------------

    print(
        "\nAttackFlow Summary:"
    )

    print(
        "-" * 70
    )

    risk_counts = defaultdict(int)

    for sequence in sequences:

        risk_counts[
            sequence[
                "risk_level"
            ]
        ] += 1

    print(
        f"Attack sequences : "
        f"{attack_sequence_count}"
    )

    print(
        f"Isolated anomalies: "
        f"{isolated_count}"
    )

    print(
        f"Critical          : "
        f"{risk_counts['Critical']}"
    )

    print(
        f"High              : "
        f"{risk_counts['High']}"
    )

    print(
        f"Medium            : "
        f"{risk_counts['Medium']}"
    )

    print(
        f"Low               : "
        f"{risk_counts['Low']}"
    )

    # -----------------------------------------------------------------------
    # Top results
    # -----------------------------------------------------------------------

    print(
        "\nTop results:"
    )

    print(
        "-" * 70
    )

    for sequence in sequences[:10]:

        ground_truth = (
            sequence[
                "_ground_truth_campaign"
            ]
            or
            "no known campaign"
        )

        print(
            f"{sequence['sequence_id']}: "
            f"{sequence['sequence_type']}, "
            f"risk={sequence['risk_score']} "
            f"({sequence['risk_level']}), "
            f"events={sequence['event_count']}, "
            f"patterns={sequence['attack_patterns']}, "
            f"attack_types={sequence['attack_types']}, "
            f"stages={sequence['stages_observed']}, "
            f"ground_truth={ground_truth}"
        )


# ===========================================================================
# Entry Point
# ===========================================================================

if __name__ == "__main__":
    run()
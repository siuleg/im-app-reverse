# Constants
TE = 0.5  # Threshold for inter-packet delays to detect bursts
TS = 0.01  # Bin size for traffic bars in shape-based normalization
DELTA = 3  # Threshold for timing correlation
GAMMA = 10  # Threshold for size correlation
ETA = 0.9  # Detection threshold for correlation


# Main Function
def identify_communicating_parties(user_traffic, channel_traffic):
    """
    Identifies if the user is a participant in the target channel.

    Args:
        user_traffic: List of intercepted traffic packets for the user.
        channel_traffic: List of traffic packets for the channel.

    Returns:
        True if the user is part of the target channel, False otherwise.
    """
    # Step 1: Extract events
    user_events = extract_events(user_traffic, TE)
    channel_events = extract_events(channel_traffic, TE)

    # Step 2: Event-based correlation
    event_correlation = calculate_event_correlation(
        user_events, channel_events, DELTA, GAMMA
    )

    # Step 3: Shape-based correlation
    user_shape = normalize_traffic_shape(user_events, TS)
    channel_shape = normalize_traffic_shape(channel_events, TS)
    shape_correlation = calculate_shape_correlation(user_shape, channel_shape)

    # Step 4: Decision based on thresholds
    if event_correlation > ETA or shape_correlation > ETA:
        return True
    return False


# Helper Functions
def extract_events(traffic, te):
    """
    Extracts events from intercepted traffic based on packet bursts.

    Args:
        traffic: List of packet (time, size) tuples.
        te: Threshold for inter-packet delays to define a burst.

    Returns:
        List of extracted events (time, size).
    """
    events = []
    current_event = []
    for i in range(len(traffic)):
        if i == 0 or traffic[i][0] - traffic[i - 1][0] < te:
            current_event.append(traffic[i])
        else:
            events.append(aggregate_event(current_event))
            current_event = [traffic[i]]
    if current_event:
        events.append(aggregate_event(current_event))
    return events


def aggregate_event(event_packets):
    """
    Aggregates packets within a burst to form a single event.

    Args:
        event_packets: List of packets in a single burst.

    Returns:
        An event represented as (time, size).
    """
    time = event_packets[-1][0]  # Time of the last packet in the burst
    size = sum(packet[1] for packet in event_packets)  # Total size of the burst
    return (time, size)


def calculate_event_correlation(user_events, channel_events, delta, gamma):
    """
    Calculates the correlation between user and channel events.

    Args:
        user_events: List of user events.
        channel_events: List of channel events.
        delta: Timing threshold for matching events.
        gamma: Size threshold for matching events.

    Returns:
        Correlation score as a fraction of matched events.
    """
    matches = 0
    for ch_event in channel_events:
        for user_event in user_events:
            if (
                abs(ch_event[0] - user_event[0]) <= delta
                and abs(ch_event[1] - user_event[1]) <= gamma
            ):
                matches += 1
                break
    return matches / len(channel_events)


def normalize_traffic_shape(events, ts):
    """
    Normalizes traffic events into a shape representation (bins).

    Args:
        events: List of events (time, size).
        ts: Bin size for traffic normalization.

    Returns:
        List of traffic bins representing the normalized traffic shape.
    """
    max_time = max(event[0] for event in events) + ts
    bins = [0] * int(max_time / ts)
    for event in events:
        bin_index = int(event[0] / ts)
        bins[bin_index] += event[1]
    return bins


def calculate_shape_correlation(user_shape, channel_shape):
    """
    Calculates the shape-based correlation between user and channel traffic.

    Args:
        user_shape: Normalized traffic shape of the user.
        channel_shape: Normalized traffic shape of the channel.

    Returns:
        Correlation score between the two shapes.
    """
    n = min(len(user_shape), len(channel_shape))
    numerator = 2 * sum(user_shape[i] * channel_shape[i] for i in range(n))
    denominator = sum(x**2 for x in user_shape[:n]) + sum(
        x**2 for x in channel_shape[:n]
    )
    return numerator / denominator


# Example Usage
user_traffic = [
    (0.01, 500),
    (0.02, 400),
    (0.8, 1500),
    ...,
]  # Intercepted traffic (time, size)
channel_traffic = [(0.015, 500), (0.8, 1500), ...]  # Channel traffic (time, size)

is_participant = identify_communicating_parties(user_traffic, channel_traffic)
print(f"Is user a participant in the channel? {is_participant}")

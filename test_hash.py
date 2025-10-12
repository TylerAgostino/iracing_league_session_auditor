from auditor import iRacingAPIHandler
import json
import os
import sys


def test_hash_equality():
    """
    Test that the hash function correctly identifies identical sessions
    regardless of the order of arrays of objects.
    """
    # Get all JSON files in the current directory
    json_files = [
        f for f in os.listdir() if f.endswith(".json") and f != "expectations.json"
    ]

    if len(json_files) < 2:
        print("Need at least two JSON files to compare.")
        return

    # Load a sample file
    with open(json_files[0], "r") as f:
        original_data = json.load(f)

    # Create a modified version where we reorder some arrays
    modified_data = json.loads(json.dumps(original_data))

    # Reorder the arrays to simulate the issue
    if (
        "admins" in modified_data
        and isinstance(modified_data["admins"], list)
        and len(modified_data["admins"]) > 1
    ):
        modified_data["admins"] = modified_data["admins"][::-1]  # Reverse the order
        print("Reversed admins array")

    if (
        "car_types" in modified_data
        and isinstance(modified_data["car_types"], list)
        and len(modified_data["car_types"]) > 1
    ):
        modified_data["car_types"] = modified_data["car_types"][::-1]
        print("Reversed car_types array")

    if (
        "track_types" in modified_data
        and isinstance(modified_data["track_types"], list)
        and len(modified_data["track_types"]) > 1
    ):
        modified_data["track_types"] = modified_data["track_types"][::-1]
        print("Reversed track_types array")

    if (
        "license_group_types" in modified_data
        and isinstance(modified_data["license_group_types"], list)
        and len(modified_data["license_group_types"]) > 1
    ):
        modified_data["license_group_types"] = modified_data["license_group_types"][
            ::-1
        ]
        print("Reversed license_group_types array")

    if (
        "event_types" in modified_data
        and isinstance(modified_data["event_types"], list)
        and len(modified_data["event_types"]) > 1
    ):
        modified_data["event_types"] = modified_data["event_types"][::-1]
        print("Reversed event_types array")

    if (
        "session_types" in modified_data
        and isinstance(modified_data["session_types"], list)
        and len(modified_data["session_types"]) > 1
    ):
        modified_data["session_types"] = modified_data["session_types"][::-1]
        print("Reversed session_types array")

    if (
        "allowed_leagues" in modified_data
        and isinstance(modified_data["allowed_leagues"], list)
        and len(modified_data["allowed_leagues"]) > 1
    ):
        modified_data["allowed_leagues"] = modified_data["allowed_leagues"][::-1]
        print("Reversed allowed_leagues array")

    if (
        "cars" in modified_data
        and isinstance(modified_data["cars"], list)
        and len(modified_data["cars"]) > 1
    ):
        modified_data["cars"] = modified_data["cars"][::-1]
        print("Reversed cars array")

    if (
        "weather" in modified_data
        and "simulated_time_offsets" in modified_data["weather"]
        and isinstance(modified_data["weather"]["simulated_time_offsets"], list)
        and len(modified_data["weather"]["simulated_time_offsets"]) > 1
    ):
        modified_data["weather"]["simulated_time_offsets"] = modified_data["weather"][
            "simulated_time_offsets"
        ][::-1]
        print("Reversed simulated_time_offsets array")

    # Now compare the hashes
    original_hash = iRacingAPIHandler._session_hash(original_data)
    modified_hash = iRacingAPIHandler._session_hash(modified_data)

    print(f"Original hash: {original_hash}")
    print(f"Modified hash: {modified_hash}")
    print(f"Hashes are equal: {original_hash == modified_hash}")

    # Also compare with a different file to ensure different sessions still have different hashes
    with open(json_files[1], "r") as f:
        different_data = json.load(f)

    different_hash = iRacingAPIHandler._session_hash(different_data)
    print(f"Different session hash: {different_hash}")
    print(f"Different from original: {original_hash != different_hash}")


if __name__ == "__main__":
    test_hash_equality()

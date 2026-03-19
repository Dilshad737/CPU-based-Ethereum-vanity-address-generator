import secrets
import multiprocessing
import time
from coincurve import PrivateKey
from eth_hash.auto import keccak

TARGET_PREFIX = "abcd"   # remove 0x for faster compare
WORKERS = multiprocessing.cpu_count()


def generate_keys(found_flag, counter):
    local_count = 0
    start = time.time()

    while not found_flag.is_set():

        # Generate private key
        pk_bytes = secrets.token_bytes(32)
        pk = PrivateKey(pk_bytes)

        # Get public key (uncompressed, skip 0x04)
        pub = pk.public_key.format(compressed=False)[1:]

        # Keccak hash
        addr = keccak(pub)[-20:]  # last 20 bytes

        # Convert only needed part to hex
        addr_hex = addr.hex()

        local_count += 1

        # FAST prefix check (no checksum, no 0x)
        if addr_hex.startswith(TARGET_PREFIX):
            print("\n🔥 MATCH FOUND 🔥")
            print("Private Key:", pk_bytes.hex())
            print("Address: 0x" + addr_hex)

            found_flag.set()
            break

        # Update shared counter every 5000 iterations
        if local_count % 5000 == 0:
            with counter.get_lock():
                counter.value += 5000

        # Occasional speed print
        if local_count % 100000 == 0:
            elapsed = time.time() - start
            print(f"[PID {multiprocessing.current_process().pid}] {local_count/elapsed:.0f} addr/sec")


def main():
    found_flag = multiprocessing.Event()
    counter = multiprocessing.Value('i', 0)

    processes = []

    print("🚀 Ultra Fast CPU Vanity Search")
    print("Target prefix: 0x" + TARGET_PREFIX)
    print("Workers:", WORKERS)

    start_time = time.time()

    for _ in range(WORKERS):
        p = multiprocessing.Process(target=generate_keys, args=(found_flag, counter))
        p.start()
        processes.append(p)

    try:
        while not found_flag.is_set():
            time.sleep(2)
            with counter.get_lock():
                total = counter.value

            elapsed = time.time() - start_time
            speed = total / elapsed if elapsed > 0 else 0

            print(f"⚡ Total Speed: {speed:.0f} addr/sec")

    except KeyboardInterrupt:
        print("\nStopping...")

    for p in processes:
        p.join()


if __name__ == "__main__":
    main()
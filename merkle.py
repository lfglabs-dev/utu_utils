import hashlib


def sha256(data: bytes) -> bytes:
    """Calculates the SHA-256 hash of the input data."""
    return hashlib.sha256(data).digest()


def double_sha256(data: bytes) -> bytes:
    """Performs double SHA-256 hashing on the input data."""
    return hashlib.sha256(hashlib.sha256(data).digest()).digest()


def reverse_byte_order(data: bytes) -> bytes:
    """Reverses the byte order of a bytes object (endian swap)."""
    return data[::-1]


def compute_merkle_root(txids):
    """Computes the Merkle root from a list of transaction IDs (txids)."""
    if not txids:
        raise ValueError("The list of transaction IDs cannot be empty.")

    if len(txids) == 1:
        return txids[0]

    txids = [reverse_byte_order(bytes.fromhex(txid)) for txid in txids]

    while len(txids) > 1:
        if len(txids) % 2 != 0:
            txids.append(txids[-1])

        new_level = []
        for i in range(0, len(txids), 2):
            concatenated = txids[i] + txids[i + 1]
            hashed = double_sha256(concatenated)
            new_level.append(hashed)

        txids = new_level

    return reverse_byte_order(txids[0]).hex()


def compute_merkle_root_from_branch(tx_id: str, merkle_branch: list) -> str:
    """Computes the Merkle root from a transaction ID and a Merkle branch."""
    current_hash = reverse_byte_order(bytes.fromhex(tx_id))

    for branch_hash, is_left in merkle_branch:
        branch_hash_bytes = reverse_byte_order(bytes.fromhex(branch_hash))

        if is_left:
            concatenated = branch_hash_bytes + current_hash
        else:
            concatenated = current_hash + branch_hash_bytes

        current_hash = double_sha256(concatenated)

    return reverse_byte_order(current_hash).hex()


def compute_merkle_branch(txids, txid):
    """Computes the Merkle branch for a given transaction ID."""
    if txid not in txids:
        raise ValueError("The transaction ID is not in the list of transaction IDs.")

    txids = [reverse_byte_order(bytes.fromhex(t)) for t in txids]
    index = txids.index(reverse_byte_order(bytes.fromhex(txid)))

    branch = []

    while len(txids) > 1:
        if len(txids) % 2 != 0:
            txids.append(txids[-1])

        new_level = []
        for i in range(0, len(txids), 2):
            concatenated = txids[i] + txids[i + 1]
            hashed = double_sha256(concatenated)
            new_level.append(hashed)

            if index in (i, i + 1):
                sibling_index = i + 1 if i == index else i
                branch.append(
                    (reverse_byte_order(txids[sibling_index]).hex(), sibling_index == i)
                )

        txids = new_level
        index //= 2

    return branch


# Test data from block: https://blockstream.info/block/000000000003ba27aa200b1cecaad478d2b00432346c3f1f3986da1afd33e506?expand

# Transaction IDs for the block
txids = [
    "8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87",
    "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4",
    "6359f0868171b1d194cbee1af2f16ea598ae8fad666d9b012c8ed2b79a236ec4",
    "e9a66845e05d5abc0ad04ec80f774a7e585c6e8db975962d069a522137b80c1d",
]

# Expected Merkle root for the block
expected_merkle_root = (
    "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
)
assert (
    compute_merkle_root(txids) == expected_merkle_root
), "Merkle root computation failed."

# Transaction ID and Merkle branch for a specific transaction
tx_id = "fff2525b8931402dd09222c50775608f75787bd2b87e56995a7bdd30f79702c4"
merkle_branch = [
    ("8c14f0db3df150123e6f3dbbf30f8b955a8249b62ac1d1ff16284aefa3d06d87", True),
    ("8e30899078ca1813be036a073bbf80b86cdddde1c96e9e9c99e9e3782df4ae49", False),
]

# Expected Merkle root from the branch
expected_merkle_root_from_branch = (
    "f3e94742aca4b5ef85488dc37c06c3282295ffec960994b2c0d5ac2a25a95766"
)
assert (
    compute_merkle_root_from_branch(tx_id, merkle_branch)
    == expected_merkle_root_from_branch
), "Merkle root from branch computation failed."

# Compute Merkle branch for a given transaction ID
computed_merkle_branch = compute_merkle_branch(txids, tx_id)
assert computed_merkle_branch == merkle_branch, "Merkle branch computation failed."

# Test data for block with a single transaction
single_txid = "fe28050b93faea61fa88c4c630f0e1f0a1c24d0082dd0e10d369e13212128f33"

# Expected Merkle root for the block with a single transaction
expected_single_tx_merkle_root = single_txid
assert (
    compute_merkle_root([single_txid]) == expected_single_tx_merkle_root
), "Merkle root computation for single transaction failed."

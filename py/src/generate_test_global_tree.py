# # generate_global_tree.py
#
# usage example (sending nodes in stderr to /dev/null):
#
# $ python src/generate_test_global_tree.py <<'EOF' 2>/dev/null
# 978257171231527130811587576456504820066317852047211009343890029541393479136 0x02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779 0x0287ac1196abb9501ac540b88e74b6a2b9476903c3f7e85e71d573c997ce1e5b
# 2216396239273623009628046076940816512923808178401142985552926513489037661413 0x02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779 0x0000000000000000000000000000000000000000000000000000000000000000
# EOF
# 05b4ca9e1caff46ebf6416f6d7192a9e562a6cf193b4fe73c30bf7d8062f0e13 # stdin
#
# read stdin for lines of "contract_address contract_state_hash commitment_tree_root", after closing
# stdin will report a root hash on stdout for this global storage merkle tree.
# nodes will be dumped on stderr.
#
# keys and values are either:
#
# - hex for big endian integers (whatever accepted by bytes.fromhex) with 0x prefix
# - base 10 integers
#
# No input validation is done for keys or values; they could be too large for example.
#
# does not accept any arguments.


async def generate_root_and_nodes(input):
    """
    Input is a generator of (key, value)
    Returns (root, nodes)
    """

    # use the testing utils
    from starkware.starknet.testing.state import StarknetState
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starknet.business_logic.state_objects import ContractState
    from copy import deepcopy

    # still create this for the ffc it creates.
    state = await StarknetState.empty()

    # StarknetState (state) -> CarriedState (state) -> ffc with DictStorage
    ffc = state.state.ffc

    # TODO: not sure why this needs to be given
    empty_contract_state = await ContractState.empty(
        state.general_config.contract_storage_commitment_tree_height, ffc
    )
    root = await PatriciaTree.empty_tree(
        ffc,
        state.general_config.global_state_commitment_tree_height,
        empty_contract_state,
    )

    # creation of starknetstate will create in 0.6.2 meaningless entries in the
    # default dictionary storage; deepcopy now to filter them out later

    initial_ignorable_state = deepcopy(ffc.storage.db)

    # using a dict here to do *some* validation, as in not to have same key
    # multiple times in the modifications to support calling this on random
    # input
    updates = {}

    for (contract_address, contract_hash, contract_commitment_tree_root) in input:
        assert type(contract_address) == int
        assert type(contract_hash) == bytes, f"{type(contract_hash)}"
        assert type(contract_commitment_tree_root) == bytes

        updates[contract_address] = await ContractState.create(
            contract_hash,
            PatriciaTree(
                root=contract_commitment_tree_root,
                height=state.general_config.contract_storage_commitment_tree_height,
            ),
        )

    # Call ParticiaTree.update directly:
    # it takes a modifications or something
    # - [key] = ContractState(contract_hash, commitment_tree_root)
    # it's last parameter facts are empty or none

    # flush the tree into storage, generate all nodes
    new_root = (await root.update(ffc, updates.items())).root

    nodes = {}
    for k, v in state.state.ffc.storage.db.items():
        if k in initial_ignorable_state and initial_ignorable_state[k] == v:
            # just filter the initial zeros and related json
            continue

        nodes[k] = v

    return (new_root, nodes)


def parse_line(s):
    s = s.strip()
    [addr, c_hash, c_root_hash] = s.split(maxsplit=2)
    # TODO: maybe map would work?
    return (parse_value(addr), parse_bytes(c_hash), parse_bytes(c_root_hash))


def parse_value(s):
    if s.startswith("0x"):
        hex = s[2:]
        if len(hex) == 0:
            return 0
        assert len(hex) % 2 == 0, f"unsupported: odd length ({len(hex)}) hex input"
        data = bytes.fromhex(hex)
        return int.from_bytes(data, "big")

    return int(s)


def parse_bytes(s):
    if s.startswith("0x"):
        hex = s[2:]
        if len(hex) == 0:
            return (0).to_bytes(32, "big")
        assert len(hex) % 2 == 0, f"unsupported: odd length ({len(hex)}) hex input"
        return bytes.fromhex(hex)

    return int(s).to_bytes(32, "big")


if __name__ == "__main__":
    import asyncio
    import sys

    assert len(sys.argv) <= 1, f"unsupported args; use stdin: {sys.argv}"

    gen = (parse_line(line) for line in sys.stdin)
    (root, nodes) = asyncio.run(generate_root_and_nodes(gen))
    print(root.hex())

    for k, v in nodes.items():
        [prefix, suffix] = k.split(b":", maxsplit=1)
        print(f"{str(prefix, 'utf-8')}:{suffix.hex()} => {v.hex()}", file=sys.stderr)

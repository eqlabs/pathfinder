# # generate_test_tree.py
#
# read stdin for lines of "key value", after closing stdin will report a root
# hash on stdout for this per-contract storage merkle tree. nodes will be
# dumped on stderr.
#
# keys and values are either:
#
# - hex for big endian integers (whatever accepted by bytes.fromhex)
# - base 10 integers
#
# No input validation is done for keys or values. Values will be put in StorageLeaf, keys will be used as ints.
#
# does not accept any arguments.


async def generate_root_and_nodes(input):
    """
    Input is a generator of (key, value)
    Returns (root, nodes)
    """

    # use the testing utils
    from starkware.starknet.testing.state import StarknetState
    from starkware.starknet.storage.starknet_storage import StorageLeaf
    from copy import deepcopy

    state = await StarknetState.empty()

    # creation of starknetstate will create in 0.6.2 meaningless entries in the
    # default dictionary storage; deepcopy now to filter them out later

    initial_ignorable_state = deepcopy(state.state.ffc.storage.db)

    # this should have no meaning on the output
    contract_address = (
        3434122877859862112550733797372700318255828812231958594412050293946922622982
    )

    # the testing state has a nice defaultdict which will create an entry when you try to request it
    # as the contract states. this is as opposed to raising KeyError
    # StarknetState (state) -> CarriedState (state?) -> contract_states (dict int => ContractCarriedState)
    contract_carried_state = state.state.contract_states[contract_address]
    assert contract_carried_state is not None

    ccs_updates = contract_carried_state.storage_updates
    # we'd be fine with anything dict alike but if this passes lets keep it for now
    assert type(ccs_updates) == dict

    for (k, v) in input:
        ccs_updates[k] = StorageLeaf(v)

    # flush the tree into storage, generate all nodes
    new_root = (
        await contract_carried_state.update(ffc=state.state.ffc)
    ).state.storage_commitment_tree.root

    nodes = {}
    for k, v in state.state.ffc.storage.db.items():
        if k in initial_ignorable_state and initial_ignorable_state[k] == v:
            # just filter the initial zeros and related json
            continue

        nodes[k] = v

    return (new_root, nodes)


def parse_line(s):
    s = s.strip()
    [key, value] = s.split(maxsplit=1)
    return (parse_value(key), parse_value(value))


def parse_value(s):
    if s.startswith("0x"):
        hex = s[2:]
        if len(hex) == 0:
            return 0
        assert len(hex) % 2 == 0, f"unsupported: odd length ({len(hex)}) hex input"
        data = bytes.fromhex(hex)
        return int.from_bytes(data, "big")

    return int(s)


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

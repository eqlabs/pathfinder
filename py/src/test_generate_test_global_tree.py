from generate_test_global_tree import generate_root_and_nodes, parse_value
import asyncio


def test_existing_example():
    contract_address = parse_value(
        "0x0797a50901fb5f57c8f231f5ce3b312851adc4b178dd557da00f6fd4d2dce006"
    )
    contract_hash = parse_value(
        "0x02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779"
    )
    contract_commitment_tree_root = parse_value(
        "0x04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028"
    )

    (root, nodes) = asyncio.run(
        generate_root_and_nodes(
            [(contract_address, contract_hash, contract_commitment_tree_root)]
        )
    )

    assert root == bytes.fromhex(
        "07b3590ce37bfe958d1b1066e05969834e5cea6fca10724f62924523bdafc7ee"
    )

    assert len(nodes) == 2

    cs_key = b"contract_state:" + bytes.fromhex(
        "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3"
    )

    # we don't care about this contents; it's json but it's order is not stable
    # so we cannot really do byte per byte equals
    assert cs_key in nodes

    pn_key = b"patricia_node:" + bytes.fromhex(
        "07b3590ce37bfe958d1b1066e05969834e5cea6fca10724f62924523bdafc7ee"
    )

    assert nodes[pn_key] == bytes.fromhex(
        "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f30797a50901fb5f57c8f231f5ce3b312851adc4b178dd557da00f6fd4d2dce006fb"
    )

from generate_test_global_tree import generate_root_and_nodes, parse_value, parse_bytes
import asyncio


def test_existing_example():
    contract_address = parse_value(
        "0x0797a50901fb5f57c8f231f5ce3b312851adc4b178dd557da00f6fd4d2dce006"
    )
    contract_hash = parse_bytes(
        "0x02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779"
    )
    contract_commitment_tree_root = parse_bytes(
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


def test_existing_example_of_two():

    c_hash = bytes.fromhex(
        "02ff4903e17f87b298ded00c44bfeb22874c5f73be2ced8f1d9d9556fb509779"
    )
    first_root = bytes.fromhex(
        "0287ac1196abb9501ac540b88e74b6a2b9476903c3f7e85e71d573c997ce1e5b"
    )

    input = [
        (
            978257171231527130811587576456504820066317852047211009343890029541393479136,
            c_hash,
            first_root,
        ),
        (
            2216396239273623009628046076940816512923808178401142985552926513489037661413,
            c_hash,
            (0).to_bytes(32, "big"),
        ),
    ]

    (root, nodes) = asyncio.run(generate_root_and_nodes(input))

    assert root == bytes.fromhex(
        "05b4ca9e1caff46ebf6416f6d7192a9e562a6cf193b4fe73c30bf7d8062f0e13"
    )

    assert len(nodes) == 5

    expected_contract_states = [
        "0624c583dc39acbe616dacfec32cc6daf56c754e645008cd58136db126525ba8",
        "032226432c9e57372cb07542bb0c3b3f502e2784ccfd26deaa8dad398cecb5d4",
    ]

    expected_pt_nodes = [
        (
            "0789650716d1a126a537fa5f32a3e794ce87347df439fbe862624064f13876c2",
            "0624c583dc39acbe616dacfec32cc6daf56c754e645008cd58136db126525ba80229ac872a344da1032254ffe7b8f6324b436a761c7a63efa68bddfa63f8b5e0fa",
        ),
        (
            "02ffc18b80a602a01211f692ec5fb9a818b8fbe6271da8521f4fe4309ae96641",
            "032226432c9e57372cb07542bb0c3b3f502e2784ccfd26deaa8dad398cecb5d400e66f91a1784d761964de85a8fd55f6cce24ff756262f9cbc404329bcf294e5fa",
        ),
        (
            "05b4ca9e1caff46ebf6416f6d7192a9e562a6cf193b4fe73c30bf7d8062f0e13",
            "0789650716d1a126a537fa5f32a3e794ce87347df439fbe862624064f13876c202ffc18b80a602a01211f692ec5fb9a818b8fbe6271da8521f4fe4309ae96641",
        ),
    ]

    for k in expected_contract_states:
        k = b"contract_state:" + bytes.fromhex(k)
        assert k in nodes
        # same as before: don't look into value

    for k, v in expected_pt_nodes:
        k = b"patricia_node:" + bytes.fromhex(k)
        v = bytes.fromhex(v)

        assert nodes[k] == v

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
    print(
        nodes[
            b"contract_state:"
            + bytes.fromhex(
                "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3"
            )
        ]
    )
    print("this shows that the values are different way around; does that matter?")
    # this is flaky wip
    print(
        bytes.fromhex(
            # json, not roundtripping through int with parse_value
            "7b22636f6e74726163745f68617368223a202230326666343930336531376638376232393864656430306334346266656232323837346335663733626532636564386631643964393535366662353039373739222c202273746f726167655f636f6d6d69746d656e745f74726565223a207b22686569676874223a203235312c2022726f6f74223a202230346662343430653863613962373466633132613232656266666530626330363538323036333337383937323236313137623938353433346332333963303238227d7d"
        )
    )
    assert nodes[
        b"contract_state:"
        + bytes.fromhex(
            "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f3"
        )
    ] == bytes.fromhex(
        # json, not roundtripping through int with parse_value
        "7b22636f6e74726163745f68617368223a202230326666343930336531376638376232393864656430306334346266656232323837346335663733626532636564386631643964393535366662353039373739222c202273746f726167655f636f6d6d69746d656e745f74726565223a207b22686569676874223a203235312c2022726f6f74223a202230346662343430653863613962373466633132613232656266666530626330363538323036333337383937323236313137623938353433346332333963303238227d7d"
    )
    assert nodes[
        b"patricia_node:"
        + bytes.fromhex(
            "07b3590ce37bfe958d1b1066e05969834e5cea6fca10724f62924523bdafc7ee"
        )
    ] == bytes.fromhex(
        "07161b591c893836263a64f2a7e0d829c92f6956148a60ce5e99a3f55c7973f30797a50901fb5f57c8f231f5ce3b312851adc4b178dd557da00f6fd4d2dce006fb"
    )

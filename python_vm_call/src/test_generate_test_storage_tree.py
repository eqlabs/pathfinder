from generate_test_storage_tree import generate_root_and_nodes, parse_value
import asyncio

def test_default_1_2():
    # couldn't get the pytest-asyncio working straight away
    # note: cairo-lang generates lot of warnings, which are hidden
    (root, nodes) = asyncio.run(generate_root_and_nodes([(1, 2)]))

    assert root == bytes.fromhex("02ab889bd35e684623df9b4ea4a4a1f6d9e0ef39b67c1293b8a89dd17e351330")
    assert len(nodes) == 2
    assert nodes[b'starknet_storage_leaf:' + bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")] == bytes.fromhex("0000000000000000000000000000000000000000000000000000000000000002")
    assert nodes[b'patricia_node:' + bytes.fromhex("02ab889bd35e684623df9b4ea4a4a1f6d9e0ef39b67c1293b8a89dd17e351330")] == bytes.fromhex("00000000000000000000000000000000000000000000000000000000000000020000000000000000000000000000000000000000000000000000000000000001fb")

def test_parse_value_hex():
    assert parse_value("0x01") == 1

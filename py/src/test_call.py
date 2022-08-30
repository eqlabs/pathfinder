from call import (
    check_cairolang_version,
    do_loop,
    EXPECTED_SCHEMA_REVISION,
    int_param,
    int_hash_or_latest,
    loop_inner,
    maybe_pending_updates,
    maybe_pending_deployed,
    maybe_pending_nonces,
    resolve_block,
    NOT_FOUND_CONTRACT_STATE,
)
import sqlite3
import io
import json
import pytest
import copy
from starkware.starknet.definitions.general_config import StarknetChainId
from starkware.starkware_utils.error_handling import WebFriendlyException


@pytest.mark.skip(
    reason="this is not a test but utility function working around pytest"
)
def test_relative_path(path):
    """
    Returns a path from this file, py/src/test_call.py
    """
    import pathlib

    # by default pytest doesn't set cwd which is interesting
    current = pathlib.Path(__file__)

    # this is a weird api but this seems to recover the dirname of the path
    dirname = current.parent
    target = dirname.joinpath(path)

    # this does either a symbolic resolution or readlink alike, seems to work
    return target.resolve()


# This only contains the tables required for call.
def inmemory_with_tables():
    con = sqlite3.connect(":memory:")
    con.isolation_level = None

    cur = con.execute("BEGIN")
    cur.executescript(
        """
        CREATE TABLE IF NOT EXISTS tree_global (
            hash        BLOB PRIMARY KEY,
            data        BLOB,
            ref_count   INTEGER
        );

        CREATE TABLE IF NOT EXISTS tree_contracts (
            hash        BLOB PRIMARY KEY,
            data        BLOB,
            ref_count   INTEGER
        );

        CREATE TABLE contract_states (
            state_hash BLOB PRIMARY KEY,
            hash       BLOB NOT NULL,
            root       BLOB NOT NULL,
            nonce      BLOB NOT NULL DEFAULT X'0000000000000000000000000000000000000000000000000000000000000000'
        );

        CREATE TABLE contracts (
            address    BLOB PRIMARY KEY,
            hash       BLOB NOT NULL
        );

        CREATE TABLE contract_code (
            hash       BLOB PRIMARY KEY,
            bytecode   BLOB,
            abi        BLOB,
            definition BLOB
        );

        -- This is missing the foreign key definition
        CREATE TABLE global_state (
            starknet_block_hash       BLOB PRIMARY KEY,
            starknet_block_number     INTEGER NOT NULL,
            starknet_block_timestamp  INTEGER NOT NULL,
            starknet_global_root      BLOB NOT NULL,
            ethereum_transaction_hash BLOB NOT NULL,
            ethereum_log_index        INTEGER NOT NULL
        );

        CREATE TABLE starknet_versions (
            id      INTEGER NOT NULL PRIMARY KEY,
            version TEXT NOT NULL UNIQUE
        );

        CREATE TABLE starknet_blocks (
            number               INTEGER PRIMARY KEY,
            hash                 BLOB    NOT NULL,
            root                 BLOB    NOT NULL,
            timestamp            INTEGER NOT NULL,
            gas_price            BLOB    NOT NULL,
            sequencer_address    BLOB    NOT NULL,
            version_id           INTEGER REFERENCES starknet_versions(id)
        );
        """
    )

    # strangely this cannot be pulled into the script, maybe pragmas have
    # different kind of semantics than what is normally executed, would explain
    # the similar behaviour of sqlite3 .dump and restore.
    #
    # apparently python sqlite does not support pragmas with parameters
    # (questionmark or named).
    assert (
        type(EXPECTED_SCHEMA_REVISION) is int
    ), f"expected schema revision must be just int, not: {type(EXPECTED_SCHEMA_REVISION)}"
    assert (
        0 <= EXPECTED_SCHEMA_REVISION < 2 ** 16
    ), f"schema revision out of range: {EXPECTED_SCHEMA_REVISION}"
    cur.execute("pragma user_version = %d" % EXPECTED_SCHEMA_REVISION)

    con.commit()
    return con


def populate_test_contract_with_132_on_3(con):
    """
    Populates a situation created with cairo-lang contract_test.py where
    the test contract has been deployed and it's memory address 132 has been
    written as 3.
    """

    # this cannot be changed without recomputing the global state root
    contract_address = (
        2483955865838519930787573649413589905962103032695051953168137837593959392116
    )
    cur = con.execute("BEGIN")

    path = test_relative_path(
        "../../crates/pathfinder/fixtures/contract_definition.json.zst"
    )

    with open(path, "rb") as file:
        # this fixture is compiled from 0.7 or 0.6 test.cairo, stored for compute contract hash tests.
        contract_definition = file.read()
        assert type(contract_definition) == bytes
        assert len(contract_definition) == 5208

        cur.execute(
            "insert into contract_code (hash, definition) values (?, ?)",
            [
                bytes.fromhex(
                    "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
                ),
                contract_definition,
            ],
        )

    cur.execute(
        "insert into contracts (address, hash) values (?, ?)",
        [
            (contract_address).to_bytes(32, "big"),
            bytes.fromhex(
                "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
            ),
        ],
    )

    cur.execute(
        "insert into tree_contracts (hash, data, ref_count) values (?, ?, 1)",
        [
            bytes.fromhex(
                "04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028"
            ),
            bytes.fromhex(
                "00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000084fb"
            ),
        ],
    )

    cur.execute(
        "insert into contract_states (state_hash, hash, root) values (?, ?, ?)",
        [
            bytes.fromhex(
                "002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5"
            ),
            bytes.fromhex(
                "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
            ),
            bytes.fromhex(
                "04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028"
            ),
        ],
    )

    cur.execute(
        "insert into tree_global (hash, data, ref_count) values (?, ?, 1)",
        [
            bytes.fromhex(
                "0704dfcbc470377c68e6f5ffb83970ebd0d7c48d5b8d2f4ed61a24e795e034bd"
            ),
            bytes.fromhex(
                "002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5057dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374fb"
            ),
        ],
    )

    # interestingly python sqlite does not accept X'0' here:
    cur.execute(
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address) values (?, 1, 1, ?, ?, ?)""",
        [
            left_pad(b"some blockhash somewhere", 32),
            bytes.fromhex(
                "0704dfcbc470377c68e6f5ffb83970ebd0d7c48d5b8d2f4ed61a24e795e034bd"
            ),
            left_pad(b"\x00", 16),
            left_pad(b"\x00", 32),
        ],
    )

    con.commit()
    return contract_address


def left_pad(b, to_length):
    # this needs to be used with the fake bytestring block hashes, as we always
    # query them left padded
    assert len(b) <= to_length
    return b"\x00" * (to_length - len(b)) + b


def default_132_on_3_scenario(con, input_jsons):
    assert isinstance(input_jsons, list) or isinstance(
        input_jsons, tuple
    ), f"input_jsons need to be a list or tuple, not a {type(input_jsons)}"
    output_catcher = io.StringIO()

    do_loop(con, input_jsons, output_catcher)

    output = output_catcher.getvalue()

    print(output)

    output = [json.loads(line) for line in output.splitlines()]

    if len(output) == 1:
        output = output[0]

    return output


def test_success():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "command": "call", "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
            f'{{ "command": "call", "at_block": "0x{(b"some blockhash somewhere").hex()}", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
            f'{{ "command": "call", "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
        ],
    )

    [number, block_hash, latest] = output
    expected = {"status": "ok", "output": ["0x" + (3).to_bytes(32, "big").hex()]}

    assert number == expected == block_hash == latest


def test_positive_directly():
    """
    this is like test_success but does it directly with the do_call, instead of the json wrapping, which hides exceptions which come from upgrading.
    """

    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    command = {
        "command": "call",
        "at_block": 1,
        "contract_address": contract_address,
        "entry_point_selector": "get_value",
        "calldata": [132],
        "gas_price": None,
        "chain": StarknetChainId.TESTNET,
    }

    con.execute("BEGIN")

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [3]


def test_called_contract_not_found():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "command": "call", "at_block": 1, "contract_address": {contract_address + 1}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}'
        ],
    )

    assert output == {"status": "error", "kind": "NO_SUCH_CONTRACT"}


def test_nested_called_contract_not_found():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            # call neighbouring contract, which doesn't exist in the global state tree
            f'{{ "command": "call", "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "call_increase_value", "calldata": [{contract_address - 1}, 132, 4], "gas_price": null, "chain": "GOERLI" }}'
        ],
    )

    # the original exception message is too long
    assert output == {"status": "error", "kind": "NO_SUCH_CONTRACT"}


def test_invalid_entry_point():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            # call not found entry point with `call_increase_value` args
            f'{{ "command": "call", "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "call_increase_value2", "calldata": [{contract_address - 1}, 132, 4], "gas_price": null, "chain": "GOERLI" }}'
        ],
    )

    assert output == {
        "status": "error",
        "kind": "INVALID_ENTRY_POINT",
    }


def test_invalid_schema_version():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    con.execute("pragma user_version = 0")
    con.commit()

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "command": "call", "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}'
        ],
    )

    assert output == {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}


def test_no_such_block():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    con.execute("delete from starknet_blocks")
    con.commit()

    output = default_132_on_3_scenario(
        con,
        (
            # there's only block 1
            # it is important that none of these have pending_updates or pending_deployed
            f'{{ "command": "call", "at_block": 99999999999, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
            f'{{ "command": "call", "at_block": "0x{(b"no such block").hex()}", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
            f'{{ "command": "call", "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
        ),
    )

    [number, block_hash, latest] = output

    expected = {"status": "error", "kind": "NO_SUCH_BLOCK"}

    assert number == expected
    assert block_hash == expected
    assert latest == expected


def test_check_cairolang_version():
    # run this here as well so that we get earlier than CI feedback
    # of another constant that needs to be upgraded
    assert check_cairolang_version()


def test_fee_estimate_on_positive_directly():
    # fee estimation is a new thing on top of a call, but returning only the estimated fee
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    con.execute("BEGIN")

    # f'{{ "command": "estimate_fee", "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null }}'
    command = {
        "command": "estimate_fee",
        "at_block": "latest",
        "contract_address": contract_address,
        "entry_point_selector": "get_value",
        "calldata": [132],
        # gas_price is None for null => use block's (zero)
        "gas_price": None,
        "chain": StarknetChainId.TESTNET,
    }

    (verb, output, _timings) = loop_inner(con, command)

    assert output == {
        "gas_consumed": 0,
        "gas_price": 0,
        "overall_fee": 0,
    }


def test_fee_estimate_on_positive():
    # fee estimation is a new thing on top of a call, but returning only the estimated fee
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    (first, second) = default_132_on_3_scenario(
        con,
        [
            f'{{ "command": "estimate_fee", "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": null, "chain": "GOERLI" }}',
            f'{{ "command": "estimate_fee", "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132], "gas_price": "0xa", "chain": "GOERLI" }}',
        ],
    )

    assert first == {
        "status": "ok",
        "output": {
            "gas_consumed": "0x" + (0).to_bytes(32, "big").hex(),
            "gas_price": "0x" + (0).to_bytes(32, "big").hex(),
            "overall_fee": "0x" + (0).to_bytes(32, "big").hex(),
        },
    }

    assert second == {
        "status": "ok",
        "output": {
            "gas_consumed": "0x" + (0x055A).to_bytes(32, "big").hex(),
            "gas_price": "0x" + (10).to_bytes(32, "big").hex(),
            "overall_fee": "0x" + (0x3584).to_bytes(32, "big").hex(),
        },
    }


def test_starknet_version_is_resolved():
    # using the existing setup, but just updating the one block to have a bogus version
    con = inmemory_with_tables()
    _ = populate_test_contract_with_132_on_3(con)

    con.execute("BEGIN")
    cursor = con.execute(
        "INSERT INTO starknet_versions (version) VALUES (?)", ["0.9.1"]
    )
    version_id = cursor.lastrowid

    con.execute("UPDATE starknet_blocks SET version_id = ?", [version_id])
    (info, _root) = resolve_block(con, "latest", None)

    assert info.starknet_version == "0.9.1"


def test_call_on_pending_updated():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")
    contract_address = "0x" + contract_address.to_bytes(32, "big").hex()

    pending_updates = maybe_pending_updates(
        {
            contract_address: [
                {"key": "0x84", "value": "0x99"},
            ]
        }
    )

    command = {
        "command": "call",
        "at_block": "latest",
        "contract_address": int_param(contract_address),
        "entry_point_selector": "get_value",
        "calldata": [132],
        "chain": StarknetChainId.MAINNET,
        "pending_updates": pending_updates,
    }

    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0x99]

    del command["pending_updates"]
    (verb, output, _timings) = loop_inner(con, command)
    assert output == [3]


def test_call_on_pending_deployed():
    con = inmemory_with_tables()
    _ = populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")
    contract_address = (
        "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d"
    )
    contract_hash = "0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"

    pending_updates = maybe_pending_updates(
        {
            contract_address: [
                {"key": "0x5", "value": "0x65"},
            ]
        }
    )

    pending_deployed = maybe_pending_deployed(
        [
            {
                "address": contract_address,
                "contract_hash": contract_hash,
            }
        ]
    )

    command = {
        "command": "call",
        "at_block": "latest",
        "contract_address": int_param(contract_address),
        "entry_point_selector": "get_value",
        "calldata": [5],
        "gas_price": None,
        "chain": StarknetChainId.MAINNET,
        "pending_updates": pending_updates,
        "pending_deployed": pending_deployed,
    }

    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0x65]

    del command["pending_updates"]
    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0]


def test_call_on_pending_deployed_through_existing():
    con = inmemory_with_tables()
    orig_contract_address = populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")
    contract_address = (
        "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d"
    )
    contract_hash = "0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"

    pending_updates = maybe_pending_updates(
        {
            contract_address: [
                {"key": "0x5", "value": "0x65"},
            ]
        }
    )

    pending_deployed = maybe_pending_deployed(
        [
            {
                "address": contract_address,
                "contract_hash": contract_hash,
            }
        ]
    )

    command = {
        "command": "call",
        "at_block": "latest",
        "contract_address": orig_contract_address,
        "entry_point_selector": "call_increase_value",
        "calldata": [
            # target contract
            int_param(contract_address),
            # address
            5,
            # increment by
            4,
        ],
        "gas_price": None,
        "chain": StarknetChainId.MAINNET,
        "pending_updates": pending_updates,
        "pending_deployed": pending_deployed,
    }

    # the call_increase_value doesn't return anything, which is a bit unfortunate.
    # the reason why this works is probably because the contract is already
    # loaded due to called contract sharing the contract.
    #
    # FIXME: add a test case for calling from existing to a new deployed contract.
    # It'll probably be easy to just modify the existing test.cairo thing we
    # already have, add a method or a return value to call_increase_value.
    (verb, output, _timings) = loop_inner(con, command)
    assert output == []


def test_call_on_reorgged_pending_block():
    """
    This was discussed during the pending implementation:

    When calling or estimating the fee on a pending block, rust side will
    always execute it on a specific block (pending's parent block). If that
    block is not found, we should default to the latest block IFF there are
    pending updates or deploys.

    This now gives meaning to the `pending_{updates,deployed}: None` vs.
    `pending_{updates,deployed}: <default>` cases.
    """

    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    existing_block = int_hash_or_latest(f'0x{(b"some blockhash somewhere").hex()}')
    reorgged_block = int_hash_or_latest(f'0x{(b"this block got reorgged").hex()}')

    commands = []

    commands.append(
        (
            {
                "command": "call",
                "at_block": existing_block,
                "contract_address": contract_address,
                "entry_point_selector": "get_value",
                "calldata": [132],
                "gas_price": None,
                "chain": StarknetChainId.MAINNET,
                "pending_updates": {
                    contract_address: [
                        {"key": 132, "value": 5},
                    ]
                },
                "pending_deployed": maybe_pending_deployed([]),
            },
            [5],
        )
    )

    commands.append(
        (
            {
                "command": "call",
                # this block is not found
                "at_block": reorgged_block,
                "contract_address": contract_address,
                "entry_point_selector": "get_value",
                "calldata": [132],
                "gas_price": None,
                "chain": StarknetChainId.MAINNET,
                # because the block is not found, the updates are not used
                "pending_updates": {
                    contract_address: [
                        {"key": 132, "value": 5},
                    ]
                },
                "pending_deployed": maybe_pending_deployed([]),
            },
            [3],
        )
    )

    # similar to above cases, but this time call on pending_deployed address.

    commands.append(
        (
            {
                "command": "call",
                "at_block": existing_block,
                "contract_address": 1234567,
                "entry_point_selector": "get_value",
                "calldata": [132],
                "gas_price": None,
                "chain": StarknetChainId.MAINNET,
                "pending_updates": {
                    1234567: [
                        {"key": 132, "value": 5},
                    ]
                },
                "pending_deployed": maybe_pending_deployed(
                    [
                        {
                            "address": 1234567,
                            "contract_hash": "0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b",
                        }
                    ]
                ),
            },
            [5],
        )
    )

    commands.append(
        (
            {
                "command": "call",
                # this block is not found
                "at_block": reorgged_block,
                "contract_address": 1234567,
                "entry_point_selector": "get_value",
                "calldata": [132],
                "gas_price": None,
                "chain": StarknetChainId.MAINNET,
                # because the block is not found, the updates are not used
                "pending_updates": {
                    1234567: [
                        {"key": 132, "value": 5},
                    ]
                },
                "pending_deployed": maybe_pending_deployed(
                    [
                        {
                            "address": 1234567,
                            "contract_hash": "0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b",
                        }
                    ]
                ),
            },
            "StarknetErrorCode.UNINITIALIZED_CONTRACT",
        )
    )

    # existing test cases calling on non-existing blocks should work as they have been,
    # because they don't define any value for pending stuffs

    con.execute("BEGIN")
    for command, expected in commands:
        try:
            (verb, output, _timings) = loop_inner(con, command)
            assert expected == output
        except WebFriendlyException as e:
            assert expected == str(e.code)


def test_static_returned_not_found_contract_state():
    # this is quite silly that we need to communicate serialized default values instead of None for not found values
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starknet.business_logic.fact_state.contract_state_objects import (
        ContractState,
    )

    dumped = (
        ContractState(b"\x00" * 32, PatriciaTree(b"\x00" * 32, 251), 0)
        .dumps(sort_keys=True)
        .encode("utf-8")
    )
    # test is to make sure the static value is up to date between versions
    assert dumped == NOT_FOUND_CONTRACT_STATE


def test_maybe_pending_nonces():
    example = {"0x123": "0x12345"}
    expected = {291: 74565}
    assert expected == maybe_pending_nonces(example)


def test_nonce_with_dummy():
    from starkware.starknet.public.abi import get_selector_from_name

    con = inmemory_with_tables()
    test_contract = populate_test_contract_with_132_on_3(con)

    path = test_relative_path("../../crates/pathfinder/fixtures/dummy_account.json.zst")

    cur = con.execute("BEGIN")

    class_hash = "00af5f6ee1c2ad961f0b1cd3fa4285cefad65a418dd105719faa5d47583eb0a8"
    zero = "0000000000000000000000000000000000000000000000000000000000000000"

    with open(path, "rb") as file:
        # this fixture is compiled from 0.10 cairo-lang repository; we hope
        # that it gets the v1 invoke nonce check
        contract_definition = file.read()

        cur.execute(
            "insert into contract_code (hash, definition) values (?, ?)",
            [
                bytes.fromhex(class_hash),
                contract_definition,
            ],
        )

    cur.executemany(
        "insert into contract_states (state_hash, hash, root, nonce) values (?, ?, ?, ?)",
        [
            # first block referred to by 0x123
            (
                bytes.fromhex(
                    "02c915dd92251d9c5ace97251a8a3929f4af71e0177f0202d9be44fa3b7b0ee6"
                ),
                bytes.fromhex(class_hash),
                bytes.fromhex(zero),
                bytes.fromhex(zero),
            ),
            # second block referred to by 0x123
            (
                bytes.fromhex(
                    "03ad994dcd3372ea369e19ef5782ec08c4f31c261edf280c362f5fb6aa93931d"
                ),
                bytes.fromhex(class_hash),
                bytes.fromhex(zero),
                (1).to_bytes(32, "big"),
            ),
        ],
    )

    # block1.tree:
    # # address used in tests
    # 0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374 0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b 0x04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028 0x0
    # # added for dummy tests
    # 0x123 0x00af5f6ee1c2ad961f0b1cd3fa4285cefad65a418dd105719faa5d47583eb0a8 0x0 0x0
    #
    # block2.tree:
    # # address used in tests
    # 0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374 0x050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b 0x04fb440e8ca9b74fc12a22ebffe0bc0658206337897226117b985434c239c028 0x0
    # # added for dummy tests
    # 0x123 0x00af5f6ee1c2ad961f0b1cd3fa4285cefad65a418dd105719faa5d47583eb0a8 0x0 0x1

    first_global_root = (
        "0764f5270a4e73449b2fb9e275c86049b4fcbf56ab53208542bfbbb0b91b08be"
    )
    second_global_root = (
        "021d10453b2e84f9a127815d697d9dc2cc01e4a42d6a70d19987a8425f557789"
    )

    # cannot use on conflict ignore with python3.8 from ubuntu 20.04
    cur.executemany(
        "insert into tree_global (hash, data) values (?, ?)",
        [
            (
                bytes.fromhex(
                    "00ce37c493172aa63687beb33a0f7649cf841220160af700ab85b045a20a0c96"
                ),
                bytes.fromhex(
                    "002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5017dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374fa"
                ),
            ),
            (
                bytes.fromhex(
                    "05d40df048370fce33a1d880280e9604e2a3904fe868106c7e978b626356194b"
                ),
                bytes.fromhex(
                    "02c915dd92251d9c5ace97251a8a3929f4af71e0177f0202d9be44fa3b7b0ee60000000000000000000000000000000000000000000000000000000000000123fa"
                ),
            ),
            (
                bytes.fromhex(
                    "06f5cc211c53a5588ab1b50a9c5b869ce62ae4697c63ffb9d53bee7d58952514"
                ),
                bytes.fromhex(
                    "03ad994dcd3372ea369e19ef5782ec08c4f31c261edf280c362f5fb6aa93931d0000000000000000000000000000000000000000000000000000000000000123fa"
                ),
            ),
            # this is shared between trees
            # (bytes.fromhex("00ce37c493172aa63687beb33a0f7649cf841220160af700ab85b045a20a0c96"), bytes.fromhex("002e9723e54711aec56e3fb6ad1bb8272f64ec92e0a43a20feed943b1d4f73c5017dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374fa")),
            (
                bytes.fromhex(first_global_root),
                bytes.fromhex(
                    "05d40df048370fce33a1d880280e9604e2a3904fe868106c7e978b626356194b00ce37c493172aa63687beb33a0f7649cf841220160af700ab85b045a20a0c96"
                ),
            ),
            (
                bytes.fromhex(second_global_root),
                bytes.fromhex(
                    "06f5cc211c53a5588ab1b50a9c5b869ce62ae4697c63ffb9d53bee7d5895251400ce37c493172aa63687beb33a0f7649cf841220160af700ab85b045a20a0c96"
                ),
            ),
        ],
    )

    cur.executemany(
        "insert into starknet_blocks (hash, number, root, timestamp, gas_price, sequencer_address, version_id) values (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                left_pad(b"another block", 32),
                2,
                bytes.fromhex(first_global_root),
                2,
                b"\x00" * 32,
                b"\x00" * 32,
                None,
            ),
            (
                left_pad(b"third block", 32),
                3,
                bytes.fromhex(second_global_root),
                3,
                b"\x00" * 32,
                b"\x00" * 32,
                None,
            ),
        ],
    )

    con.commit()

    # not to mess with the existing tests and the populated data, create the
    # second and third block with a new account at two different nonces

    # this will be used as a basis for the other commands with the `dict(base, **updates)` signature
    base_command = {
        "command": "estimate_fee",
        "at_block": b"some blockhash somewhere",
        "contract_address": 0x123,
        # cairo-lang asserts that this is None
        # "entry_point_selector": "__execute__",
        # this should be: target address, target selector, input len, input..
        "calldata": [test_contract, get_selector_from_name("get_value"), 1, 132],
        "gas_price": 0x1,
        "chain": StarknetChainId.MAINNET,
        "nonce": 0,
        "version": 1,
    }

    commands = []
    commands.append(
        (
            # on the first block there is no contract by that address
            base_command,
            "StarknetErrorCode.UNINITIALIZED_CONTRACT",
        )
    )
    commands.append(
        (
            # in this block the acct contract has been deployed, so it has nonce=0
            dict(base_command, at_block=b"another block"),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        )
    )
    commands.append(
        (
            dict(base_command, at_block=b"another block", nonce=1),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )
    commands.append(
        (
            dict(base_command, at_block=b"another block", nonce=2),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )
    commands.append(
        (
            # in this block the stored nonce is 1
            dict(base_command, at_block=b"third block", nonce=1),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        )
    )
    commands.append(
        (
            dict(base_command, at_block=b"third block", nonce=2),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )
    commands.append(
        (
            # in this block the stored nonce is 1
            dict(base_command, at_block=b"third block", nonce=3),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )
    commands.append(
        (
            # now the nonce requirement should had been advanced to 2
            dict(
                base_command,
                at_block=b"third block",
                nonce=1,
                pending_nonces={0x123: 2},
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )
    commands.append(
        (
            # now the nonce requirement should had been advanced to 2
            dict(
                base_command,
                at_block=b"third block",
                nonce=2,
                pending_nonces={0x123: 2},
            ),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        )
    )
    commands.append(
        (
            dict(
                base_command,
                at_block=b"third block",
                nonce=3,
                pending_nonces={0x123: 2},
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        )
    )

    con.execute("BEGIN")
    nth = 1
    for command, expected in commands:
        try:
            print(command)
            (verb, output, _timings) = loop_inner(con, command)
            assert expected == output, f"example {nth}"
        except WebFriendlyException as e:
            assert expected == str(e.code), f"example {nth}"
        nth += 1


# Rest of the test cases require a mainnet or goerli database in some path.


@pytest.mark.skip(reason="this requires up to 2804 block synced database")
def test_failing_mainnet_tx2():
    con = sqlite3.connect(test_relative_path("../../mainnet.sqlite"))
    con.execute("BEGIN")

    # this is running fee estimation on existing transaction from mainnet, on the block before
    # txhash = 0xccb3808126726235eee5818e6298e5cc2c9db3731442d66ad63f7e3f7d396d
    #
    # easiest way to find this command is to add logging into the call.py::loop_inner:
    #    print(f"{command}", file=sys.stderr, flush=True)
    # then reproduce it in a test case like this, let automatic formatting do it's job.
    command = {
        "command": "estimate_fee",
        "contract_address": 45915111574649954983606422480229741823594314537836586888051448850027079668,
        "calldata": [
            1,
            2087021424722619777119509474943472645767659996348769578120564519014510906823,
            232670485425082704932579856502088130646006032362877466777181098476241604910,
            0,
            3,
            3,
            1993141595574381281542654435135626980310393893133465032682864365884756205412,
            8235300000000000,
            0,
            1,
        ],
        "entry_point_selector": 617075754465154585683856897856256838130216341506379215893724690153393808813,
        "at_block": b"\x01G\xc4\xb0\xf7\x02\x07\x93\x84\xe2m\x9d4\xa1^wX\x88\x1e2\xb2\x19\xfch\xc0v\xb0\x9d\x0b\xe1?\x8c",
        "gas_price": 21367239423,
        "signature": [
            0x10E400D046147777C2AC5645024E1EE81C86D90B52D76AB8A8125E5F49612F9,
            0xADB92739205B4626FEFB533B38D0071EB018E6FF096C98C17A6826B536817B,
        ],
        "max_fee": 0x12C72866EFA9B,
        "chain": StarknetChainId.MAINNET,
    }

    (verb, output, _timings) = loop_inner(con, command)

    print(_timings)

    # this is correct in 0.10, not in 0.9.1
    assert output == {
        "gas_consumed": 10102,
        "gas_price": 21367239423,
        "overall_fee": 215851852651146,
    }


@pytest.mark.skip(reason="this requires an early goerli database")
def test_positive_streamed_on_early_goerli_block_without_deployed():
    con = sqlite3.connect(test_relative_path("../../goerli.sqlite"))
    con.execute("BEGIN")

    # this is copypasted from the get_state_update
    pending_updates = {
        "0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451": [
            {"key": "0x5", "value": "0x0"}
        ],
        # this is the one we care about, it was written at block 5 to 0x64
        "0x543e54f26ae33686f57da2ceebed98b340c3a78e9390931bd84fb711d5caabc": [
            {"key": "0x5", "value": "0x22b"}
        ],
        # leave this out since it was deployed, which we should list as well, but not yet
        # "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d": [
        #     {"key": "0x5", "value": "0x65"},
        #     {
        #         "key": "0x2199e6fee3564246f851c45e8268c79fe073caff90420878b3fb11458d77139",
        #         "value": "0x563e7b33aef472392dfb1a491f739295bad7105e669a6183c6f1a76124bafd1",
        #     },
        # ],
        "0x2fb7ff5b1b474e8e691f5bebad9aa7aa3009f6ef22ccc2816f96cdfe217604d": [
            {"key": "0x5", "value": "0x64"}
        ],
    }

    pending_updates = maybe_pending_updates(pending_updates)

    without_updates = {
        "command": "call",
        "at_block": 6,
        "contract_address": int_param(
            "0x543e54f26ae33686f57da2ceebed98b340c3a78e9390931bd84fb711d5caabc"
        ),
        "entry_point_selector": "get_value",
        "calldata": [5],
        "gas_price": None,
        "chain": StarknetChainId.TESTNET,
    }

    with_updates = copy.deepcopy(without_updates)
    with_updates["pending_updates"] = pending_updates

    (verb, output, _timings) = loop_inner(con, without_updates)
    assert output == [0x64]

    (verb, output, _timings) = loop_inner(con, with_updates)
    assert output == [0x22B]


@pytest.mark.skip(reason="this requires an early goerli database")
def test_positive_streamed_on_early_goerli_block_with_deployed():
    con = sqlite3.connect(test_relative_path("../../goerli.sqlite"))
    con.execute("BEGIN")

    # this is copypasted from the get_state_update
    pending_updates = {
        "0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451": [
            {"key": "0x5", "value": "0x0"}
        ],
        # this is the one we care about, it was written at block 5 to 0x64
        "0x543e54f26ae33686f57da2ceebed98b340c3a78e9390931bd84fb711d5caabc": [
            {"key": "0x5", "value": "0x22b"}
        ],
        "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d": [
            {"key": "0x5", "value": "0x65"},
            {
                "key": "0x2199e6fee3564246f851c45e8268c79fe073caff90420878b3fb11458d77139",
                "value": "0x563e7b33aef472392dfb1a491f739295bad7105e669a6183c6f1a76124bafd1",
            },
        ],
        "0x2fb7ff5b1b474e8e691f5bebad9aa7aa3009f6ef22ccc2816f96cdfe217604d": [
            {"key": "0x5", "value": "0x64"}
        ],
    }

    pending_updates = maybe_pending_updates(pending_updates)

    # this matches sequencer state update
    pending_deployed = [
        {
            "address": "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d",
            "contract_hash": "0x010455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8",
        }
    ]

    # pending deployed contracts need to be included because otherwise the contract => class mapping could not be resolved.
    pending_deployed = maybe_pending_deployed(pending_deployed)

    without_updates = {
        "command": "call",
        "at_block": 6,
        "contract_address": int_param(
            "0x543e54f26ae33686f57da2ceebed98b340c3a78e9390931bd84fb711d5caabc"
        ),
        "entry_point_selector": "get_value",
        "calldata": [5],
        "gas_price": None,
        "chain": StarknetChainId.TESTNET,
    }

    with_updates = copy.deepcopy(without_updates)
    with_updates["pending_updates"] = pending_updates
    with_updates["pending_deployed"] = pending_deployed

    (verb, output, _timings) = loop_inner(con, without_updates)
    assert output == [0x64]

    (verb, output, _timings) = loop_inner(con, with_updates)
    assert output == [0x22B]

    # "tail case"
    #
    # I was initially confused why does this case seem to work without pushing
    # all pending_deployed's contract_hashes to be loaded at the StateSelector,
    # because such was required in the minimal standalone case but not here.
    # the reason must be that other pending_updates had prompted fetching of
    # the required (and shared) contract_hash so this didn't seem to require
    # it.

    on_newly_deployed = {
        "command": "call",
        "at_block": 6,
        "contract_address": int_param(
            "0x18b2088accbd652384e5ac545fd249095cb17bdc709868d1d748094d52b9f7d"
        ),
        "entry_point_selector": "get_value",
        "calldata": [5],
        "gas_price": None,
        "chain": StarknetChainId.MAINNET,
        "pending_updates": pending_updates,
        "pending_deployed": pending_deployed,
    }

    (verb, output, _timings) = loop_inner(con, on_newly_deployed)
    assert output == [0x65]

    del on_newly_deployed["pending_updates"][on_newly_deployed["contract_address"]]

    (verb, output, _timings) = loop_inner(con, on_newly_deployed)
    assert output == [0]

from call import do_loop, loop_inner, EXPECTED_SCHEMA_REVISION, check_cairolang_version
import sqlite3
import io
import json


# this is from 64a7f6aed9757d3d8d6c28bd972df73272b0cb0a of cairo-lang
# with needless parts ripped out of it. updated for 0.9.0
SIMPLIFIED_TEST_CONTRACT = """
%lang starknet

from starkware.starknet.common.syscalls import (storage_read, storage_write)

@contract_interface
namespace MyContract:
    func increase_value(address : felt, value : felt):
    end
end

@external
func increase_value{syscall_ptr : felt*}(address : felt, value : felt):
    let (prev_value) = storage_read(address=address)
    storage_write(address, value=prev_value + 1)
    return ()
end

@external
func call_increase_value{syscall_ptr : felt*, range_check_ptr}(
        contract_address : felt, address : felt, value : felt):
    MyContract.increase_value(contract_address=contract_address, address=address, value=value)
    return ()
end

@external
func get_value{syscall_ptr : felt*}(address : felt) -> (res : felt):
    let (value) = storage_read(address=address)
    return (res=value)
end
"""


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
            root       BLOB NOT NULL
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

        CREATE TABLE starknet_blocks (
            number               INTEGER PRIMARY KEY,
            hash                 BLOB    NOT NULL,
            root                 BLOB    NOT NULL,
            timestamp            INTEGER NOT NULL,
            gas_price            BLOB    NOT NULL,
            sequencer_address    BLOB    NOT NULL
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

    def left_pad(b, to_length):
        assert len(b) <= to_length
        return b"\x00" * (to_length - len(b)) + b

    cur.execute(
        "insert into contract_code (hash, definition) values (?, ?)",
        [
            bytes.fromhex(
                "050b2148c0d782914e0b12a1a32abe5e398930b7e914f82c65cb7afce0a0ab9b"
            ),
            compile_test_contract(),
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
            left_pad(b"0", 16),
            left_pad(b"0", 32),
        ],
    )

    con.commit()
    return contract_address


def compile_test_contract():
    from starkware.starknet.compiler.compile import compile_starknet_codes
    import zstandard

    # crates/pathfinder/fixtures/contract_definition.json.zst used to be the same, but is no longer with 0.9

    raw = compile_starknet_codes(
        [(SIMPLIFIED_TEST_CONTRACT, "-")], debug_info=False
    ).serialize()
    # we use 10 over at pathfinder, but for tests 1 is probably better
    compressor = zstandard.ZstdCompressor(level=1)
    return compressor.compress(raw)


def default_132_on_3_scenario(con, input_jsons):
    assert isinstance(input_jsons, list) or isinstance(
        input_jsons, tuple
    ), f"input_jsons need to be a list or tuple, not a {type(input_jsons)}"
    output_catcher = io.StringIO()

    do_loop(con, input_jsons, output_catcher)

    output = output_catcher.getvalue()

    print(output)

    def strip_timings(loaded_json):
        """
        Remove the timings because that's not really interesting for our tests here,
        cannot be compared for equality.
        """
        del loaded_json["timings"]
        return loaded_json

    output = [strip_timings(json.loads(line)) for line in output.splitlines()]

    if len(output) == 1:
        output = output[0]

    return output


def test_success():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
            f'{{ "at_block": "0x{(b"some blockhash somewhere").hex()}", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
            f'{{ "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
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
        "at_block": 1,
        "contract_address": contract_address,
        "entry_point_selector": "get_value",
        "calldata": [132],
    }

    con.execute("BEGIN")

    output = loop_inner(con, command)

    assert output == [3]


def test_called_contract_not_found():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    # con.execute("delete from contract_code")
    # con.execute("delete from contracts")
    # con.execute("delete from contract_states")
    # con.commit()

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "at_block": 1, "contract_address": {contract_address + 1}, "entry_point_selector": "get_value", "calldata": [132] }}'
        ],
    )

    # TODO: this should probably be understood to a nicer one
    assert output == {"status": "error", "kind": "NO_SUCH_CONTRACT"}


def test_nested_called_contract_not_found():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    output = default_132_on_3_scenario(
        con,
        [
            # call neighbouring contract, which doesn't exist in the global state tree
            f'{{ "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "call_increase_value", "calldata": [{contract_address - 1}, 132, 4] }}'
        ],
    )

    # the original exception message is too long

    assert output == {
        "status": "failed",
        "exception": "StarknetErrorCode.TRANSACTION_FAILED",
    }


def test_invalid_schema_version():
    con = inmemory_with_tables()
    contract_address = populate_test_contract_with_132_on_3(con)

    con.execute("pragma user_version = 0")
    con.commit()

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "at_block": 1, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}'
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
            f'{{ "at_block": 99999999999, "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
            f'{{ "at_block": "0x{(b"no such block").hex()}", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
            f'{{ "at_block": "latest", "contract_address": {contract_address}, "entry_point_selector": "get_value", "calldata": [132] }}',
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

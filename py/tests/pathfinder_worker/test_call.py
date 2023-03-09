from abc import abstractmethod
import dataclasses
import io
import json
import sqlite3

import pytest
import zstandard

import pathfinder_worker.call as call

from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.services.api.gateway.transaction import InvokeFunction, Declare
from starkware.starknet.services.api.contract_class import ContractClass
from starkware.starkware_utils.error_handling import WebFriendlyException

from pathfinder_worker.call import (
    EXPECTED_SCHEMA_REVISION,
    NOT_FOUND_CONTRACT_STATE,
    Call,
    Command,
    EstimateFee,
    check_cairolang_version,
    do_loop,
    loop_inner,
    resolve_block,
)


def test_command_parsing_estimate_fee():
    input = """{
        "verb":"ESTIMATE_FEE",
        "at_block":"0x736f6d6520626c6f636b6861736820736f6d657768657265",
        "chain":"TESTNET",
        "gas_price":"0xa",
        "pending_updates":{"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451":[{"key":"0x5","value":"0x0"}]},
        "pending_deployed":[
            {
                "address":"0x7c38021eb1f890c5d572125302fe4a0d2f79d38b018d68a9fcd102145d4e451",
                "contract_hash":"0x10455c752b86932ce552f2b0fe81a880746649b9aee7e0d842bf3f52378f9f8"
            }
        ],
        "pending_nonces":{"0x123":"0x1"},
        "pending_timestamp": 0,
        "transaction":{
            "type":"INVOKE_FUNCTION",
            "version":"0x100000000000000000000000000000000",
            "max_fee":"0x0",
            "signature":[],
            "nonce":null,
            "contract_address":"0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
            "entry_point_selector":"0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0",
            "calldata":["132"]}
    }"""
    command = Command.Schema().loads(input)
    assert command == EstimateFee(
        at_block="0x736f6d6520626c6f636b6861736820736f6d657768657265",
        chain=call.Chain.TESTNET,
        gas_price=10,
        pending_updates={
            0x7C38021EB1F890C5D572125302FE4A0D2F79D38B018D68A9FCD102145D4E451: [
                call.StorageDiff(key=5, value=0)
            ]
        },
        pending_deployed=[
            call.DeployedContract(
                address=0x7C38021EB1F890C5D572125302FE4A0D2F79D38B018D68A9FCD102145D4E451,
                contract_hash=0x10455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8,
            )
        ],
        pending_nonces={0x123: 1},
        pending_timestamp=0,
        transaction=InvokeFunction(
            version=0x100000000000000000000000000000000,
            contract_address=0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374,
            calldata=[132],
            entry_point_selector=0x26813D396FDB198E9EAD934E4F7A592A8B88A059E45AB0EB6EE53494E8D45B0,
            nonce=None,
            max_fee=0,
            signature=[],
        ),
    )
    assert command.has_pending_data()


def test_command_parsing_call():
    input = """{
        "verb":"CALL",
        "at_block":"latest",
        "chain":"TESTNET2",
        "pending_updates":{
            "0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374":[
                {"key":"0x84","value":"0x4"}
            ]
        },
        "pending_deployed":[],
        "pending_nonces":{},
        "pending_timestamp": 0,
        "contract_address":"0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
        "calldata":["0x84"],
        "entry_point_selector":"0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0"
    }"""
    command = Command.Schema().loads(input)
    assert command == Call(
        at_block="latest",
        chain=call.Chain.TESTNET2,
        pending_updates={
            0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374: [
                call.StorageDiff(key=0x84, value=4)
            ]
        },
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        contract_address=0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374,
        calldata=[0x84],
        entry_point_selector=0x26813D396FDB198E9EAD934E4F7A592A8B88A059E45AB0EB6EE53494E8D45B0,
    )
    assert command.has_pending_data()


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

        CREATE TABLE class_definitions (
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
        0 <= EXPECTED_SCHEMA_REVISION < 2**16
    ), f"schema revision out of range: {EXPECTED_SCHEMA_REVISION}"
    cur.execute("pragma user_version = %d" % EXPECTED_SCHEMA_REVISION)

    con.commit()
    return con


def calculate_contract_state_hash(
    class_hash: int, contract_root: int, nonce: int
) -> int:
    contract_state_hash_version = 0

    h = pedersen_hash(class_hash, contract_root)
    h = pedersen_hash(h, nonce)
    h = pedersen_hash(h, contract_state_hash_version)

    return h


@dataclasses.dataclass
class Node:
    @abstractmethod
    def hash(self) -> int:
        pass

    @abstractmethod
    def serialize(self) -> bytes:
        pass


@dataclasses.dataclass
class BinaryNode(Node):
    left: Node
    right: Node

    def hash(self) -> int:
        return pedersen_hash(self.left.hash(), self.right.hash())

    def serialize(self) -> bytes:
        return felt_to_bytes(self.left.hash()) + felt_to_bytes(self.right.hash())


@dataclasses.dataclass
class EdgeNode(Node):
    path: int
    path_length: int
    child: Node

    def hash(self) -> int:
        return pedersen_hash(self.child.hash(), self.path) + self.path_length

    def serialize(self) -> bytes:
        return (
            felt_to_bytes(self.child.hash())
            + felt_to_bytes(self.path)
            + self.path_length.to_bytes(length=1, byteorder="big")
        )


@dataclasses.dataclass
class LeafNode(Node):
    value: int

    def hash(self) -> int:
        return self.value

    def serialize(self) -> bytes:
        raise NotImplementedError


def felt_to_bytes(v: int) -> bytes:
    return v.to_bytes(length=32, byteorder="big")


def test_edge_node_serialize():
    expected = bytes.fromhex(
        "00000000000000000000000000000000000000000000000000000000000000030000000000000000000000000000000000000000000000000000000000000084fb"
    )
    e = EdgeNode(path=132, path_length=251, child=LeafNode(value=3))
    assert e.serialize() == expected


def test_edge_node_hash():
    expected = 0x04FB440E8CA9B74FC12A22EBFFE0BC0658206337897226117B985434C239C028
    e = EdgeNode(path=132, path_length=251, child=LeafNode(value=3))
    assert e.hash() == expected


def populate_test_contract_with_132_on_3(con):
    """
    Populates a situation created with cairo-lang contract_test.py where
    the test contract has been deployed and it's memory address 132 has been
    written as 3.
    """

    # this cannot be changed without recomputing the global state root
    contract_address = 0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374
    class_hash = 0x050B2148C0D782914E0B12A1A32ABE5E398930B7E914F82C65CB7AFCE0A0AB9B

    cur = con.execute("BEGIN")

    path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/contract_definition.json.zst"
    )

    with open(path, "rb") as file:
        # this fixture is compiled from 0.7 or 0.6 test.cairo, stored for compute contract hash tests.
        contract_definition = file.read()
        assert len(contract_definition) == 5208

        cur.execute(
            "insert into class_definitions (hash, definition) values (?, ?)",
            [
                felt_to_bytes(class_hash),
                contract_definition,
            ],
        )

    # contract storage
    root_node = EdgeNode(path=132, path_length=251, child=LeafNode(value=3))
    contract_root = root_node.hash()
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
            felt_to_bytes(contract_root),
            root_node.serialize(),
        ],
    )

    contract_state_hash = calculate_contract_state_hash(class_hash, contract_root, 0)

    cur.execute(
        "insert into contract_states (state_hash, hash, root) values (?, ?, ?)",
        [
            felt_to_bytes(contract_state_hash),
            felt_to_bytes(class_hash),
            felt_to_bytes(contract_root),
        ],
    )

    # global state tree
    root_node = EdgeNode(
        path=contract_address,
        path_length=251,
        child=LeafNode(value=contract_state_hash),
    )
    state_root = root_node.hash()
    cur.execute(
        "insert into tree_global (hash, data, ref_count) values (?, ?, 1)",
        [
            felt_to_bytes(state_root),
            root_node.serialize(),
        ],
    )

    # interestingly python sqlite does not accept X'0' here:
    cur.execute(
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address) values (?, 1, 1, ?, ?, ?)""",
        [
            b"some blockhash somewhere".rjust(32, b"\x00"),
            felt_to_bytes(state_root),
            b"\x00" * 16,
            b"\x00" * 32,
        ],
    )

    con.commit()

    return contract_address, contract_state_hash


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
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    contract_address = hex(contract_address)
    entry_point = hex(get_selector_from_name("get_value"))

    common_command_data = f'"contract_address": "{contract_address}", "entry_point_selector": "{entry_point}", "calldata": ["0x84"], "gas_price": 0, "chain": "TESTNET", "pending_updates": {{}}, "pending_deployed": [], "pending_nonces": {{}}, "pending_timestamp": 0'

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "verb": "CALL", "at_block": "1", {common_command_data} }}',
            f'{{ "verb": "CALL", "at_block": "0x{(b"some blockhash somewhere").hex()}", {common_command_data} }}',
            f'{{ "verb": "CALL", "at_block": "latest", {common_command_data} }}',
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
    (contract_address, _) = populate_test_contract_with_132_on_3(con)

    command = Call(
        at_block="1",
        chain=call.Chain.TESTNET,
        contract_address=contract_address,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[132],
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
    )

    con.execute("BEGIN")

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [3]


def test_called_contract_not_found():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    entry_point = hex(get_selector_from_name("get_value"))

    common_command_data = f'"entry_point_selector": "{entry_point}", "calldata": ["0x84"], "gas_price": 0, "chain": "TESTNET", "pending_updates": {{}}, "pending_deployed": [], "pending_nonces": {{}}, "pending_timestamp": 0'

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "verb": "CALL", "at_block": "1", "contract_address": "{hex(contract_address + 1)}", {common_command_data}}}'
        ],
    )

    assert output == {"status": "error", "kind": "NO_SUCH_CONTRACT"}


def test_nested_called_contract_not_found():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    entry_point = hex(get_selector_from_name("call_increase_value"))

    common_command_data = '"gas_price": 0, "chain": "TESTNET", "pending_updates": {}, "pending_deployed": [], "pending_nonces": {}, "pending_timestamp": 0'

    output = default_132_on_3_scenario(
        con,
        [
            # call neighbouring contract, which doesn't exist in the global state tree
            f'{{ "verb": "CALL", "at_block": "1", "contract_address": "{hex(contract_address)}", "entry_point_selector": "{entry_point}", "calldata": ["{hex(contract_address - 1)}", "0x84", "0x4"], {common_command_data} }}'
        ],
    )

    # the original exception message is too long
    assert output == {"status": "error", "kind": "NO_SUCH_CONTRACT"}


def test_invalid_entry_point():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    entry_point = hex(get_selector_from_name("call_increase_value2"))

    common_command_data = '"gas_price": 0, "chain": "TESTNET", "pending_updates": {}, "pending_deployed": [], "pending_nonces": {}, "pending_timestamp": 0'
    output = default_132_on_3_scenario(
        con,
        [
            # call not found entry point with `call_increase_value` args
            f'{{ "verb": "CALL", "at_block": "1", "contract_address": "{hex(contract_address)}", "entry_point_selector": "{entry_point}", "calldata": ["{hex(contract_address - 1)}", "0x84", "0x4"], {common_command_data} }}'
        ],
    )

    assert output == {
        "status": "error",
        "kind": "INVALID_ENTRY_POINT",
    }


def test_invalid_schema_version():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    contract_address = hex(contract_address)
    entry_point = hex(get_selector_from_name("get_value"))

    common_command_data = f'"entry_point_selector": "{entry_point}", "calldata": ["0x84"], "gas_price": 0, "chain": "TESTNET", "pending_updates": {{}}, "pending_deployed": [], "pending_nonces": {{}}, "pending_timestamp": 0'

    con.execute("pragma user_version = 0")
    con.commit()

    output = default_132_on_3_scenario(
        con,
        [
            f'{{ "verb": "CALL", "at_block": "1", "contract_address": "{contract_address}", {common_command_data} }}'
        ],
    )

    assert output == {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}


def test_no_such_block():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    contract_address = hex(contract_address)
    entry_point = hex(get_selector_from_name("get_value"))

    common_command_data = f'"contract_address": "{contract_address}", "entry_point_selector": "{entry_point}", "calldata": ["0x84"], "gas_price": 0, "chain": "TESTNET", "pending_updates": {{}}, "pending_deployed": [], "pending_nonces": {{}}, "pending_timestamp": 0'

    con.execute("delete from starknet_blocks")
    con.commit()

    output = default_132_on_3_scenario(
        con,
        (
            # there's only block 1
            # it is important that none of these have pending_updates or pending_deployed
            f'{{ "verb": "CALL", "at_block": "99999999999", {common_command_data} }}',
            f'{{ "verb": "CALL", "at_block": "0x{(b"no such block").hex()}", {common_command_data} }}',
            f'{{ "verb": "CALL", "at_block": "latest", {common_command_data} }}',
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
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=0,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transaction=InvokeFunction(
            version=0x100000000000000000000000000000000,
            contract_address=contract_address,
            calldata=[132],
            entry_point_selector=get_selector_from_name("get_value"),
            nonce=None,
            max_fee=0,
            signature=[],
        ),
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == {
        "gas_consumed": 0,
        "gas_price": 0,
        "overall_fee": 0,
    }


def test_fee_estimate_for_declare_transaction_directly():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)

    path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/contract_definition.json.zst"
    )

    with open(path, "rb") as file:
        contract_definition = file.read()
        contract_definition = zstandard.decompress(contract_definition)
        contract_definition = contract_definition.decode("utf-8")
        contract_definition = ContractClass.Schema().loads(contract_definition)

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transaction=Declare(
            version=0x100000000000000000000000000000000,
            max_fee=0,
            signature=[],
            nonce=0,
            contract_class=contract_definition,
            sender_address=contract_address,
        ),
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == {
        "gas_consumed": 1341,
        "gas_price": 1,
        "overall_fee": 1341,
    }


def test_fee_estimate_on_positive():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    contract_address = hex(contract_address)
    entry_point = hex(get_selector_from_name("get_value"))

    command = """{{
        "verb":"ESTIMATE_FEE",
        "at_block":"latest",
        "chain":"TESTNET",
        "gas_price":"{gas_price}",
        "pending_updates":{{}},
        "pending_deployed":[],
        "pending_nonces":{{}},
        "pending_timestamp":0,
        "transaction":{{
            "type":"INVOKE_FUNCTION",
            "version":"0x100000000000000000000000000000000",
            "max_fee":"0x0",
            "signature":[],
            "nonce":null,
            "contract_address":"{contract_address}",
            "entry_point_selector":"{entry_point}",
            "calldata":["132"]
        }}
    }}"""

    (first, second) = default_132_on_3_scenario(
        con,
        [
            json.dumps(
                json.loads(
                    command.format(
                        gas_price="0x0",
                        contract_address=contract_address,
                        entry_point=entry_point,
                    )
                )
            ),
            json.dumps(
                json.loads(
                    command.format(
                        gas_price="0xa",
                        contract_address=contract_address,
                        entry_point=entry_point,
                    )
                )
            ),
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
    populate_test_contract_with_132_on_3(con)

    con.execute("BEGIN")
    cursor = con.execute(
        "INSERT INTO starknet_versions (version) VALUES (?)", ["0.9.1"]
    )
    version_id = cursor.lastrowid

    con.execute("UPDATE starknet_blocks SET version_id = ?", [version_id])
    (info, _root) = resolve_block(con, "latest", 0)

    assert info.starknet_version == "0.9.1"


def test_call_on_pending_updated():
    con = inmemory_with_tables()
    (contract_address, _) = populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")

    command = Call(
        at_block="latest",
        chain=call.Chain.MAINNET,
        contract_address=contract_address,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[132],
        pending_updates={contract_address: [call.StorageDiff(key=0x84, value=0x99)]},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
    )

    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0x99]

    command = dataclasses.replace(command, pending_updates={})
    (verb, output, _timings) = loop_inner(con, command)
    assert output == [3]


def test_call_on_pending_deployed():
    con = inmemory_with_tables()
    populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")

    contract_address = 0x18B2088ACCBD652384E5AC545FD249095CB17BDC709868D1D748094D52B9F7D
    contract_hash = 0x050B2148C0D782914E0B12A1A32ABE5E398930B7E914F82C65CB7AFCE0A0AB9B

    command = Call(
        at_block="latest",
        chain=call.Chain.MAINNET,
        contract_address=contract_address,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[5],
        pending_updates={contract_address: [call.StorageDiff(key=0x5, value=0x65)]},
        pending_deployed=[
            call.DeployedContract(address=contract_address, contract_hash=contract_hash)
        ],
        pending_nonces={},
        pending_timestamp=0,
    )

    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0x65]

    command = dataclasses.replace(command, pending_updates={})
    (verb, output, _timings) = loop_inner(con, command)
    assert output == [0]


def test_call_on_pending_deployed_through_existing():
    con = inmemory_with_tables()
    (orig_contract_address, _) = populate_test_contract_with_132_on_3(con)
    con.execute("BEGIN")

    contract_address = 0x18B2088ACCBD652384E5AC545FD249095CB17BDC709868D1D748094D52B9F7D
    contract_hash = 0x050B2148C0D782914E0B12A1A32ABE5E398930B7E914F82C65CB7AFCE0A0AB9B

    command = Call(
        at_block="latest",
        chain=call.Chain.MAINNET,
        contract_address=orig_contract_address,
        entry_point_selector=get_selector_from_name("call_increase_value"),
        calldata=[
            # target contract
            contract_address,
            # address
            5,
            # increment by
            4,
        ],
        pending_updates={contract_address: [call.StorageDiff(key=0x5, value=0x65)]},
        pending_deployed=[
            call.DeployedContract(address=contract_address, contract_hash=contract_hash)
        ],
        pending_nonces={},
        pending_timestamp=0,
    )

    # the call_increase_value doesn't return anything, which is a bit unfortunate.
    # the reason why this works is probably because the contract is already
    # loaded due to called contract sharing the contract.
    #
    # FIXME: add a test case for calling from existing to a new deployed contract.
    # It'll probably be easy to just modify the existing test.cairo thing we
    # already have, add a method or a return value to call_increase_value.
    (_verb, output, _timings) = loop_inner(con, command)
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
    (contract_address, _) = populate_test_contract_with_132_on_3(con)

    existing_block = f'0x{(b"some blockhash somewhere").hex()}'
    reorgged_block = f'0x{(b"this block got reorgged").hex()}'

    commands = [
        (
            Call(
                at_block=existing_block,
                chain=call.Chain.MAINNET,
                contract_address=contract_address,
                entry_point_selector=get_selector_from_name("get_value"),
                calldata=[132],
                pending_updates={
                    contract_address: [call.StorageDiff(key=132, value=5)]
                },
                pending_deployed=[],
                pending_nonces={},
                pending_timestamp=0,
            ),
            [5],
        ),
        (
            Call(
                # this block is not found
                at_block=reorgged_block,
                chain=call.Chain.MAINNET,
                contract_address=contract_address,
                entry_point_selector=get_selector_from_name("get_value"),
                calldata=[132],
                # because the block is not found, the updates are not used
                pending_updates={
                    contract_address: [call.StorageDiff(key=132, value=5)]
                },
                pending_deployed=[],
                pending_nonces={},
                pending_timestamp=0,
            ),
            [3],
        ),
        # similar to above cases, but this time call on pending_deployed address.
        (
            Call(
                at_block=existing_block,
                chain=call.Chain.MAINNET,
                contract_address=1234567,
                entry_point_selector=get_selector_from_name("get_value"),
                calldata=[132],
                pending_updates={1234567: [call.StorageDiff(key=132, value=5)]},
                pending_deployed=[
                    call.DeployedContract(
                        address=1234567,
                        contract_hash=0x050B2148C0D782914E0B12A1A32ABE5E398930B7E914F82C65CB7AFCE0A0AB9B,
                    )
                ],
                pending_nonces={},
                pending_timestamp=0,
            ),
            [5],
        ),
        (
            Call(
                # this block is not found
                at_block=reorgged_block,
                chain=call.Chain.MAINNET,
                contract_address=1234567,
                entry_point_selector=get_selector_from_name("get_value"),
                calldata=[132],
                # because the block is not found, the updates are not used
                pending_updates={1234567: [call.StorageDiff(key=132, value=5)]},
                pending_deployed=[
                    call.DeployedContract(
                        address=1234567,
                        contract_hash=0x050B2148C0D782914E0B12A1A32ABE5E398930B7E914F82C65CB7AFCE0A0AB9B,
                    )
                ],
                pending_nonces={},
                pending_timestamp=0,
            ),
            "StarknetErrorCode.UNINITIALIZED_CONTRACT",
        ),
    ]

    # existing test cases calling on non-existing blocks should work as they have been,
    # because they don't define any value for pending stuffs

    con.execute("BEGIN")
    for nth, (command, expected) in enumerate(commands):
        try:
            (verb, output, _timings) = loop_inner(con, command)
            assert expected == output, f"{nth + 1}th example"
        except WebFriendlyException as e:
            assert expected == str(e.code), f"{nth + 1}th example"


def test_static_returned_not_found_contract_state():
    # this is quite silly that we need to communicate serialized default values instead of None for not found values
    from starkware.starknet.business_logic.fact_state.contract_state_objects import (
        ContractState,
    )
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )

    dumped = (
        ContractState(b"\x00" * 32, PatriciaTree(b"\x00" * 32, 251), 0)
        .dumps(sort_keys=True)
        .encode("utf-8")
    )
    # test is to make sure the static value is up to date between versions
    assert dumped == NOT_FOUND_CONTRACT_STATE


def test_nonce_with_dummy():
    from starkware.starknet.public.abi import get_selector_from_name

    con = inmemory_with_tables()
    (
        test_contract_address,
        test_contract_state_hash,
    ) = populate_test_contract_with_132_on_3(con)

    path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/dummy_account.json.zst"
    )

    cur = con.execute("BEGIN")

    class_hash = 0x00AF5F6EE1C2AD961F0B1CD3FA4285CEFAD65A418DD105719FAA5D47583EB0A8

    with open(path, "rb") as file:
        # this fixture is compiled from 0.10 cairo-lang repository; we hope
        # that it gets the v1 invoke nonce check
        contract_definition = file.read()

        cur.execute(
            "insert into class_definitions (hash, definition) values (?, ?)",
            [
                felt_to_bytes(class_hash),
                contract_definition,
            ],
        )

    # contract states (storage is empty for account contract)
    account_contract_state_hash_with_nonce_0 = calculate_contract_state_hash(
        class_hash, 0, 0
    )
    account_contract_state_hash_with_nonce_1 = calculate_contract_state_hash(
        class_hash, 0, 1
    )

    cur.executemany(
        "insert into contract_states (state_hash, hash, root, nonce) values (?, ?, ?, ?)",
        [
            # first block referred to by 0x123
            (
                felt_to_bytes(account_contract_state_hash_with_nonce_0),
                felt_to_bytes(class_hash),
                felt_to_bytes(0),
                felt_to_bytes(0),
            ),
            # second block referred to by 0x123
            (
                felt_to_bytes(account_contract_state_hash_with_nonce_1),
                felt_to_bytes(class_hash),
                felt_to_bytes(0),
                felt_to_bytes(1),
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

    # global tree
    account_contract_node_with_nonce_0 = EdgeNode(
        path=0x123,
        path_length=250,
        child=LeafNode(value=account_contract_state_hash_with_nonce_0),
    )
    account_contract_node_with_nonce_1 = EdgeNode(
        path=0x123,
        path_length=250,
        child=LeafNode(value=account_contract_state_hash_with_nonce_1),
    )
    test_contract_node = EdgeNode(
        path=test_contract_address & (2**250 - 1),
        path_length=250,
        child=LeafNode(value=test_contract_state_hash),
    )

    first_root = BinaryNode(
        left=account_contract_node_with_nonce_0, right=test_contract_node
    )
    second_root = BinaryNode(
        left=account_contract_node_with_nonce_1, right=test_contract_node
    )

    # cannot use on conflict ignore with python3.8 from ubuntu 20.04
    cur.executemany(
        "insert into tree_global (hash, data) values (?, ?)",
        [
            (
                felt_to_bytes(account_contract_node_with_nonce_0.hash()),
                account_contract_node_with_nonce_0.serialize(),
            ),
            (
                felt_to_bytes(account_contract_node_with_nonce_1.hash()),
                account_contract_node_with_nonce_1.serialize(),
            ),
            (
                felt_to_bytes(test_contract_node.hash()),
                test_contract_node.serialize(),
            ),
            (
                felt_to_bytes(first_root.hash()),
                first_root.serialize(),
            ),
            (felt_to_bytes(second_root.hash()), second_root.serialize()),
        ],
    )

    cur.executemany(
        "insert into starknet_blocks (hash, number, root, timestamp, gas_price, sequencer_address, version_id) values (?, ?, ?, ?, ?, ?, ?)",
        [
            (
                b"another block".rjust(32, b"\x00"),
                2,
                felt_to_bytes(first_root.hash()),
                2,
                b"\x00" * 32,
                b"\x00" * 32,
                None,
            ),
            (
                b"third block".rjust(32, b"\x00"),
                3,
                felt_to_bytes(second_root.hash()),
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
    base_transaction = InvokeFunction(
        version=0x100000000000000000000000000000001,
        contract_address=0x123,
        # this should be: target address, target selector, input len, input..
        calldata=[test_contract_address, get_selector_from_name("get_value"), 1, 132],
        entry_point_selector=None,
        nonce=0,
        max_fee=0,
        signature=[],
    )
    base_command = EstimateFee(
        at_block=f'0x{(b"some blockhash somewhere").hex()}',
        chain=call.Chain.MAINNET,
        gas_price=0x1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transaction=base_transaction,
    )

    commands = [
        (
            # on the first block there is no contract by that address
            base_command,
            "StarknetErrorCode.UNINITIALIZED_CONTRACT",
        ),
        (
            # in this block the acct contract has been deployed, so it has nonce=0
            dataclasses.replace(base_command, at_block=f'0x{(b"another block").hex()}'),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"another block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=1),
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"another block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=2),
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # in this block the stored nonce is 1
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=1),
            ),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=2),
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # in this block the stored nonce is 1
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=3),
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # now the nonce requirement should had been advanced to 2
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=1),
                pending_nonces={0x123: 2},
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # now the nonce requirement should had been advanced to 2
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=2),
                pending_nonces={0x123: 2},
            ),
            {"gas_consumed": 1400, "gas_price": 1, "overall_fee": 1400},
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transaction=dataclasses.replace(base_transaction, nonce=3),
                pending_nonces={0x123: 2},
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
    ]

    con.execute("BEGIN")
    for nth, (command, expected) in enumerate(commands):
        try:
            print(command)
            (verb, output, _timings) = loop_inner(con, command)
            assert expected == output, f"{nth + 1}th example"
        except WebFriendlyException as exc:
            assert expected == str(exc.code), f"{nth + 1}th example"


# Rest of the test cases require a mainnet or testnet database in some path.


@pytest.mark.skip(reason="this requires up to 2804 block synced database")
def test_failing_mainnet_tx2():
    con = sqlite3.connect(test_relative_path("../../../mainnet.sqlite"))
    con.execute("BEGIN")

    # this is running fee estimation on existing transaction from mainnet, on the block before
    # txhash = 0xccb3808126726235eee5818e6298e5cc2c9db3731442d66ad63f7e3f7d396d
    #
    # easiest way to find this command is to add logging into the call.py::loop_inner:
    #    print(f"{command}", file=sys.stderr, flush=True)
    # then reproduce it in a test case like this, let automatic formatting do it's job.
    command = EstimateFee(
        at_block="0x0147c4b0f702079384e26d9d34a15e7758881e32b219fc68c076b09d0be13f8c",
        chain=call.Chain.MAINNET,
        gas_price=21367239423,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transaction=InvokeFunction(
            version=0,
            contract_address=45915111574649954983606422480229741823594314537836586888051448850027079668,
            calldata=[
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
            entry_point_selector=617075754465154585683856897856256838130216341506379215893724690153393808813,
            nonce=None,
            max_fee=0x12C72866EFA9B,
            signature=[
                0x10E400D046147777C2AC5645024E1EE81C86D90B52D76AB8A8125E5F49612F9,
                0xADB92739205B4626FEFB533B38D0071EB018E6FF096C98C17A6826B536817B,
            ],
        ),
    )

    (_verb, output, timings) = loop_inner(con, command)

    print(timings)

    # this is correct in 0.10, not in 0.9.1
    assert output == {
        "gas_consumed": 10102,
        "gas_price": 21367239423,
        "overall_fee": 215851852651146,
    }


@pytest.mark.skip(reason="this requires an early goerli database")
def test_positive_streamed_on_early_goerli_block_without_deployed():
    con = sqlite3.connect(test_relative_path("../../../goerli.sqlite"))
    con.execute("BEGIN")

    with_updates = Call(
        at_block="6",
        chain=call.Chain.TESTNET,
        contract_address=0x543E54F26AE33686F57DA2CEEBED98B340C3A78E9390931BD84FB711D5CAABC,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[5],
        # this is from the corresponding state update for block 6
        pending_updates={
            0x7C38021EB1F890C5D572125302FE4A0D2F79D38B018D68A9FCD102145D4E451: [
                call.StorageDiff(key=0x5, value=0x0)
            ],
            # this is the one we care about, it was written at block 5 to 0x64
            0x543E54F26AE33686F57DA2CEEBED98B340C3A78E9390931BD84FB711D5CAABC: [
                call.StorageDiff(key=0x5, value=0x22B)
            ],
            # leave this out since it was deployed, which we should list as well, but not yet
            # 0x18B2088ACCBD652384E5AC545FD249095CB17BDC709868D1D748094D52B9F7D: [
            #     call.StorageDiff(key=0x5, value=0x65),
            #     call.StorageDiff(
            #         key=0x2199E6FEE3564246F851C45E8268C79FE073CAFF90420878B3FB11458D77139,
            #         value=0x563E7B33AEF472392DFB1A491F739295BAD7105E669A6183C6F1A76124BAFD1,
            #     ),
            # ],
            0x2FB7FF5B1B474E8E691F5BEBAD9AA7AA3009F6EF22CCC2816F96CDFE217604D: [
                call.StorageDiff(key=0x5, value=0x64),
            ],
        },
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
    )

    without_updates = dataclasses.replace(with_updates, pending_updates={})

    (verb, output, _timings) = loop_inner(con, without_updates)
    assert output == [0x64]

    (verb, output, _timings) = loop_inner(con, with_updates)
    assert output == [0x22B]


@pytest.mark.skip(reason="this requires a mainnet database with block 11486")
def test_timestamp_dependent_pending_call():
    con = sqlite3.connect(test_relative_path("../../../mainnet.sqlite"))
    con.execute("BEGIN")

    # This call fails if we are just using the timestamp from the block specified
    # by `at_block`. Execution succeeds only with the correct timestamp from the pending
    # block.
    c = Call(
        at_block="0x74cc50f4b8083835682bbe1489a4b1474053e4f6a35c66b8bb25b2e700630f9",
        chain=call.Chain.MAINNET,
        pending_updates={
            0x3D39F7248FB2BFB960275746470F7FB470317350AD8656249EC66067559E892: [
                call.StorageDiff(
                    key=0x57E3AC4C831E9CE78DE8142D212350256E7263262456048615D1800F91A021,
                    value=0xDE21C10E8E2457F,
                ),
                call.StorageDiff(
                    key=0x41FB32DAA5E26566D482776D5F8ABFF389DA500038A86A288F5ADB39276AD55,
                    value=0x27FC7A436ABEEE,
                ),
                call.StorageDiff(
                    key=0x5A827682859FAFF64442160965F441FC4344F998E6818244814B04A830749EA,
                    value=0x6380C4AD,
                ),
                call.StorageDiff(
                    key=0x69010E0D78ABB0652354B78994622E24A9E47A8D30D5C4C0C9FB2DF3DBC04CF,
                    value=0xDE2B4696C7152F6,
                ),
                call.StorageDiff(
                    key=0x747A639BB6DBAE6D3A00A22E5E976EB21F6A8C0D87B25A9E77C50759D7066CB,
                    value=0x9737843489E05,
                ),
            ],
        },
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=1669383496,
        contract_address=3193647238523375300127598243000966435117811015280340811133237455989949224134,
        calldata=[],
        entry_point_selector=227334030968744315992796982100494617316223563777432855541120004521101595501,
        gas_price=0,
    )

    (verb, output, _timings) = loop_inner(con, c)


@pytest.mark.skip(reason="this requires an early goerli database")
def test_positive_streamed_on_early_goerli_block_with_deployed():
    con = sqlite3.connect(test_relative_path("../../../goerli.sqlite"))
    con.execute("BEGIN")

    # this is from the corresponding state update for block 6
    pending_updates = {
        0x7C38021EB1F890C5D572125302FE4A0D2F79D38B018D68A9FCD102145D4E451: [
            call.StorageDiff(key=0x5, value=0x0)
        ],
        # this is the one we care about, it was written at block 5 to 0x64
        0x543E54F26AE33686F57DA2CEEBED98B340C3A78E9390931BD84FB711D5CAABC: [
            call.StorageDiff(key=0x5, value=0x22B)
        ],
        0x18B2088ACCBD652384E5AC545FD249095CB17BDC709868D1D748094D52B9F7D: [
            call.StorageDiff(key=0x5, value=0x65),
            call.StorageDiff(
                key=0x2199E6FEE3564246F851C45E8268C79FE073CAFF90420878B3FB11458D77139,
                value=0x563E7B33AEF472392DFB1A491F739295BAD7105E669A6183C6F1A76124BAFD1,
            ),
        ],
        0x2FB7FF5B1B474E8E691F5BEBAD9AA7AA3009F6EF22CCC2816F96CDFE217604D: [
            call.StorageDiff(key=0x5, value=0x64),
        ],
    }

    pending_deployed = [
        call.DeployedContract(
            address=0x18B2088ACCBD652384E5AC545FD249095CB17BDC709868D1D748094D52B9F7D,
            contract_hash=0x010455C752B86932CE552F2B0FE81A880746649B9AEE7E0D842BF3F52378F9F8,
        )
    ]

    with_updates = Call(
        at_block="6",
        chain=call.Chain.TESTNET,
        contract_address=0x543E54F26AE33686F57DA2CEEBED98B340C3A78E9390931BD84FB711D5CAABC,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[5],
        pending_updates=pending_updates,
        pending_deployed=pending_deployed,
        pending_nonces={},
        pending_timestamp=0,
    )

    without_updates = dataclasses.replace(
        with_updates, pending_updates={}, pending_deployed=[]
    )

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
    on_newly_deployed = Call(
        at_block="6",
        chain=call.Chain.TESTNET,
        contract_address=pending_deployed[0].address,
        entry_point_selector=get_selector_from_name("get_value"),
        calldata=[5],
        pending_updates=pending_updates,
        pending_deployed=pending_deployed,
        pending_nonces={},
        pending_timestamp=0,
    )

    (verb, output, _timings) = loop_inner(con, on_newly_deployed)
    assert output == [0x65]

    del on_newly_deployed.pending_updates[on_newly_deployed.contract_address]

    (verb, output, _timings) = loop_inner(con, on_newly_deployed)
    assert output == [0]

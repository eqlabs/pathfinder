from abc import abstractmethod
import dataclasses
import io
import json
import sqlite3
from typing import Tuple

import pytest
import zstandard

import pathfinder_worker.call as call

from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.cairo.common.poseidon_hash import poseidon_hash
from starkware.starknet.public.abi import get_selector_from_name
from starkware.starknet.services.api.gateway.transaction import (
    InvokeFunction,
    Declare,
    DeprecatedDeclare,
    DeployAccount,
)
from starkware.starknet.services.api.feeder_gateway.response_objects import (
    FeeEstimationInfo,
    TransactionSimulationInfo,
)
from starkware.starknet.services.api.contract_class.contract_class import (
    DeprecatedCompiledClass,
    ContractClass,
)
from starkware.starkware_utils.error_handling import StarkException

from pathfinder_worker.call import (
    EXPECTED_SCHEMA_REVISION,
    NOT_FOUND_CONTRACT_STATE,
    Call,
    Command,
    EstimateFee,
    SimulateTx,
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
        "transactions":[{
            "type":"INVOKE_FUNCTION",
            "version":"0x100000000000000000000000000000000",
            "max_fee":"0x0",
            "signature":[],
            "nonce":null,
            "contract_address":"0x57dde83c18c0efe7123c36a52d704cf27d5c38cdf0b1e1edc3b0dae3ee4e374",
            "entry_point_selector":"0x26813d396fdb198e9ead934e4f7a592a8b88a059e45ab0eb6ee53494e8d45b0",
            "calldata":["132"]}]
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
        transactions=[
            InvokeFunction(
                version=0x100000000000000000000000000000000,
                sender_address=0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374,
                calldata=[132],
                entry_point_selector=0x26813D396FDB198E9EAD934E4F7A592A8B88A059E45AB0EB6EE53494E8D45B0,
                nonce=None,
                max_fee=0,
                signature=[],
            )
        ],
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

        CREATE TABLE IF NOT EXISTS tree_class (
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

        CREATE TABLE class_definitions (
            hash       BLOB PRIMARY KEY,
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
            version_id           INTEGER REFERENCES starknet_versions(id),
            class_commitment     BLOB
        );

        -- Stores CASM compiler versions.
        CREATE TABLE casm_compiler_versions (
            id      INTEGER     PRIMARY KEY NOT NULL,
            version TEXT        NOT NULL UNIQUE
        );

        -- Stores compiled CASM for Sierra classes.
        CREATE TABLE casm_definitions (
            hash                        BLOB    PRIMARY KEY NOT NULL,
            compiled_class_hash         BLOB    NOT NULL,
            definition                  BLOB    NOT NULL,
            compiler_version_id         INTEGER NOT NULL REFERENCES casm_compiler_versions(id),
            FOREIGN KEY(hash) REFERENCES class_definitions(hash) ON DELETE CASCADE
        );

        -- Stores class commitment leaf hash to compiled class hash mappings.
        CREATE TABLE class_commitment_leaves (
            hash                BLOB    PRIMARY KEY NOT NULL,
            compiled_class_hash BLOB    NOT NULL
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


def calculate_class_commitment_leaf(compiled_class_hash: int) -> int:
    contract_class_hash_version = int.from_bytes(
        b"CONTRACT_CLASS_LEAF_V0", byteorder="big"
    )

    return poseidon_hash(contract_class_hash_version, compiled_class_hash)


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
    declare_class(cur, class_hash, path)

    # contract storage
    root_node = EdgeNode(path=132, path_length=251, child=LeafNode(value=3))
    contract_root = root_node.hash()
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
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address, class_commitment) values (?, 1, 1, ?, ?, ?, ?)""",
        [
            b"some blockhash somewhere".rjust(32, b"\x00"),
            felt_to_bytes(state_root),
            b"\x00" * 16,
            b"\x00" * 32,
            None,
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
    expected = {"status": "ok", "output": ["0x03"]}

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
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            InvokeFunction(
                version=0x100000000000000000000000000000000,
                sender_address=contract_address,
                calldata=[132],
                entry_point_selector=get_selector_from_name("get_value"),
                nonce=None,
                max_fee=0,
                signature=[],
            )
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        FeeEstimationInfo(
            gas_usage=1258,
            gas_price=1,
            overall_fee=1258,
        )
    ]


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
        contract_definition = DeprecatedCompiledClass.Schema().loads(
            contract_definition
        )

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            DeprecatedDeclare(
                version=0x100000000000000000000000000000000,
                max_fee=0,
                signature=[],
                nonce=0,
                contract_class=contract_definition,
                sender_address=1,
            )
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        FeeEstimationInfo(
            gas_usage=1251,
            gas_price=1,
            overall_fee=1251,
        )
    ]


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
        "transactions":[{{
            "type":"INVOKE_FUNCTION",
            "version":"0x100000000000000000000000000000000",
            "max_fee":"0x0",
            "signature":[],
            "nonce":null,
            "contract_address":"{contract_address}",
            "entry_point_selector":"{entry_point}",
            "calldata":["132"]
        }}]
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
        "output": [
            {
                "gas_consumed": "0x0",
                "gas_price": "0x0",
                "overall_fee": "0x0",
            }
        ],
    }

    assert second == {
        "status": "ok",
        "output": [
            {
                "gas_consumed": "0x04ea",
                "gas_price": "0x0a",
                "overall_fee": "0x03124",
            },
        ],
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
    (info, _root, _class_commitment) = resolve_block(con, "latest", 0)

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
        except StarkException as e:
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
    declare_class(cur, class_hash, path)

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
                felt_to_bytes(1),
                b"\x00" * 32,
                None,
            ),
            (
                b"third block".rjust(32, b"\x00"),
                3,
                felt_to_bytes(second_root.hash()),
                3,
                felt_to_bytes(1),
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
        version=2**128 + 1,
        sender_address=0x123,
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
        transactions=[base_transaction],
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
            [FeeEstimationInfo(gas_usage=1266, gas_price=1, overall_fee=1266)],
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"another block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=1)],
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"another block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=2)],
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # in this block the stored nonce is 1
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=1)],
            ),
            [FeeEstimationInfo(gas_usage=1266, gas_price=1, overall_fee=1266)],
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=2)],
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # in this block the stored nonce is 1
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=3)],
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # now the nonce requirement should had been advanced to 2
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=1)],
                pending_nonces={0x123: 2},
            ),
            "StarknetErrorCode.INVALID_TRANSACTION_NONCE",
        ),
        (
            # now the nonce requirement should had been advanced to 2
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=2)],
                pending_nonces={0x123: 2},
            ),
            [FeeEstimationInfo(gas_usage=1266, gas_price=1, overall_fee=1266)],
        ),
        (
            dataclasses.replace(
                base_command,
                at_block=f'0x{(b"third block").hex()}',
                transactions=[dataclasses.replace(base_transaction, nonce=3)],
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
        except StarkException as exc:
            assert expected == str(exc.code), f"{nth + 1}th example"


def setup_dummy_account_and_sierra_contract(cur: sqlite3.Cursor) -> Tuple[int, int]:
    # declare classes
    sierra_class_path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/sierra-1.0.0.alpha5-starknet-format.json.zst"
    )
    sierra_class_hash = (
        0x4E70B19333AE94BD958625F7B61CE9EEC631653597E68645E13780061B2136C
    )
    declare_class(cur, sierra_class_hash, sierra_class_path)

    dummy_account_contract_path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/dummy_account.json.zst"
    )
    dummy_account_contract_class_hash = (
        0x00AF5F6EE1C2AD961F0B1CD3FA4285CEFAD65A418DD105719FAA5D47583EB0A8
    )
    declare_class(cur, dummy_account_contract_class_hash, dummy_account_contract_path)

    # CASM class
    compiled_class_path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/sierra-1.0.0.alpha5-starknet-format-compiled-casm.json.zst"
    )
    compiled_class_hash = (
        0x00711C0C3E56863E29D3158804AAC47F424241EDA64DB33E2CC2999D60EE5105
    )
    add_casm_definition(
        cur,
        sierra_class_hash,
        compiled_class_hash,
        "cairo-lang-starknet 1.0.0-alpha.5",
        compiled_class_path,
    )

    # Class commitment tree
    class_commitment_root = EdgeNode(
        sierra_class_hash,
        251,
        LeafNode(value=calculate_class_commitment_leaf(compiled_class_hash)),
    )
    cur.executemany(
        "insert into tree_class (hash, data) values (?, ?)",
        [
            (
                felt_to_bytes(class_commitment_root.hash()),
                class_commitment_root.serialize(),
            ),
        ],
    )

    sierra_class_state_hash = calculate_contract_state_hash(sierra_class_hash, 0, 0)
    dummy_account_contract_state_hash = calculate_contract_state_hash(
        dummy_account_contract_class_hash, 0, 0
    )

    # Contract states
    cur.executemany(
        "insert into contract_states (state_hash, hash, root, nonce) values (?, ?, ?, ?)",
        [
            (
                felt_to_bytes(sierra_class_state_hash),
                felt_to_bytes(sierra_class_hash),
                felt_to_bytes(0),
                felt_to_bytes(0),
            ),
            (
                felt_to_bytes(dummy_account_contract_state_hash),
                felt_to_bytes(dummy_account_contract_class_hash),
                felt_to_bytes(0),
                felt_to_bytes(0),
            ),
        ],
    )

    # Global tree
    dummy_account_contract_address = 0x123
    sierra_contract_address = (
        0x57DDE83C18C0EFE7123C36A52D704CF27D5C38CDF0B1E1EDC3B0DAE3EE4E374
    )

    dummy_account_contract_node = EdgeNode(
        path=dummy_account_contract_address,
        path_length=250,
        child=LeafNode(value=dummy_account_contract_state_hash),
    )
    sierra_contract_node = EdgeNode(
        path=sierra_contract_address & (2**250 - 1),
        path_length=250,
        child=LeafNode(value=sierra_class_state_hash),
    )
    storage_root_node = BinaryNode(
        left=dummy_account_contract_node, right=sierra_contract_node
    )

    cur.executemany(
        "insert into tree_global (hash, data) values (?, ?)",
        [
            (
                felt_to_bytes(dummy_account_contract_node.hash()),
                dummy_account_contract_node.serialize(),
            ),
            (
                felt_to_bytes(sierra_contract_node.hash()),
                sierra_contract_node.serialize(),
            ),
            (felt_to_bytes(storage_root_node.hash()), storage_root_node.serialize()),
        ],
    )

    # Block
    cur.execute(
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address, class_commitment) values (?, 1, 1, ?, ?, ?, ?)""",
        [
            b"some blockhash somewhere".rjust(32, b"\x00"),
            felt_to_bytes(storage_root_node.hash()),
            b"\x00" * 16,
            b"\x00" * 32,
            felt_to_bytes(class_commitment_root.hash()),
        ],
    )

    return (dummy_account_contract_address, sierra_contract_address)


def test_call_sierra_contract_directly():
    con = inmemory_with_tables()
    cur = con.execute("BEGIN")
    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)
    con.commit()

    con.execute("BEGIN")

    # Test calling the Sierra contract directly
    command = Call(
        at_block="1",
        chain=call.Chain.TESTNET,
        contract_address=sierra_contract_address,
        entry_point_selector=get_selector_from_name("test"),
        calldata=[1, 2, 3],
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
    )

    (_verb, output, _timings) = loop_inner(con, command)
    assert output == [1, 2]


def test_call_sierra_contract_through_account():
    con = inmemory_with_tables()
    cur = con.execute("BEGIN")
    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)
    con.commit()

    con.execute("BEGIN")

    # Test calling the Sierra contract through the Cairo 0.x account contract
    command = Call(
        at_block="1",
        chain=call.Chain.TESTNET,
        contract_address=dummy_account_contract_address,
        entry_point_selector=get_selector_from_name("__execute__"),
        calldata=[sierra_contract_address, get_selector_from_name("test"), 3, 1, 2, 3],
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
    )

    (_verb, output, _timings) = loop_inner(con, command)
    assert output == [1, 2]


def test_sierra_invoke_function_through_account():
    con = inmemory_with_tables()
    cur = con.execute("BEGIN")
    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)
    con.commit()

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            InvokeFunction(
                version=2**128 + 1,
                sender_address=dummy_account_contract_address,
                calldata=[
                    sierra_contract_address,
                    get_selector_from_name("test"),
                    3,
                    1,
                    2,
                    3,
                ],
                nonce=0,
                max_fee=0,
                signature=[],
            )
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        FeeEstimationInfo(
            gas_usage=3715,
            gas_price=1,
            overall_fee=3715,
        )
    ]


def test_sierra_declare_through_account():
    con = inmemory_with_tables()
    cur = con.execute("BEGIN")
    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)
    con.commit()

    sierra_class_definition_path = test_relative_path(
        "./sierra_class_definition.json.zst"
    )

    with open(sierra_class_definition_path, "rb") as file:
        class_definition = file.read()
        class_definition = zstandard.decompress(class_definition).decode("utf-8")
        class_definition = ContractClass.loads(class_definition)

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            Declare(
                version=0x100000000000000000000000000000002,
                sender_address=dummy_account_contract_address,
                contract_class=class_definition,
                compiled_class_hash=0x05BBE92A11E8C31CAD885C72877F12E6EDFB5250AF54430DFA8ED7504C548417,
                nonce=0,
                max_fee=0,
                signature=[],
            )
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        FeeEstimationInfo(
            gas_usage=1251,
            gas_price=1,
            overall_fee=1251,
        )
    ]


def test_deploy_account(): ## here
    con = inmemory_with_tables()

    cur = con.execute("BEGIN")

    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)

    con.commit()

    dummy_account_contract_class_hash = (
        0x00AF5F6EE1C2AD961F0B1CD3FA4285CEFAD65A418DD105719FAA5D47583EB0A8
    )
    deployed_dummy_account_address = (
        0x338E12DB8A3ED26AF4A49FD91317A59F86EADED02FC1BC91F956987D9F31C2E
    )

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            DeployAccount(
                class_hash=dummy_account_contract_class_hash,
                contract_address_salt=0,
                constructor_calldata=[],
                version=0x100000000000000000000000000000001,
                nonce=0,
                max_fee=0,
                signature=[],
            ),
            InvokeFunction(
                version=2**128 + 1,
                sender_address=deployed_dummy_account_address,
                calldata=[
                    sierra_contract_address,
                    get_selector_from_name("test"),
                    3,
                    1,
                    2,
                    3,
                ],
                nonce=1,
                max_fee=0,
                signature=[],
            ),
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        # DEPLOY_ACCOUNT
        FeeEstimationInfo(
            gas_usage=3096,
            gas_price=1,
            overall_fee=3096,
        ),
        # INVOKE_FUNCTION through deployed account
        FeeEstimationInfo(
            gas_usage=3715,
            gas_price=1,
            overall_fee=3715,
        ),
    ]


def test_deploy_newly_declared_account():
    con = inmemory_with_tables()

    cur = con.execute("BEGIN")

    # Block
    cur.execute(
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address, class_commitment) values (?, 1, 1, ?, ?, ?, ?)""",
        [
            b"some blockhash somewhere".rjust(32, b"\x00"),
            felt_to_bytes(0),
            b"\x00" * 16,
            b"\x00" * 32,
            felt_to_bytes(0),
        ],
    )

    con.commit()

    dummy_account_contract_path = test_relative_path(
        "../../../crates/gateway-test-fixtures/fixtures/contracts/dummy_account.json.zst"
    )
    dummy_account_contract_class_hash = (
        0x0791563DA22895F1E398B689866718346106C0CC71207A4ADA68E6687CE1BADF
    )

    with open(dummy_account_contract_path, "rb") as file:
        dummy_account_contract_definition = file.read()
        dummy_account_contract_definition = zstandard.decompress(
            dummy_account_contract_definition
        )
        dummy_account_contract_definition = dummy_account_contract_definition.decode(
            "utf-8"
        )
        dummy_account_contract_definition = DeprecatedCompiledClass.Schema().loads(
            dummy_account_contract_definition
        )

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            # DECLARE an account contract class
            DeprecatedDeclare(
                version=0x100000000000000000000000000000000,
                max_fee=0,
                signature=[],
                nonce=0,
                contract_class=dummy_account_contract_definition,
                sender_address=1,
            ),
            # DEPLOY_ACCOUNT the class declared in the previous transaction
            DeployAccount(
                class_hash=dummy_account_contract_class_hash,
                contract_address_salt=0,
                constructor_calldata=[],
                version=0x100000000000000000000000000000001,
                nonce=0,
                max_fee=0,
                signature=[],
            ),
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        # DECLARE an account contract class
        {
            "gas_consumed": 1251,
            "gas_price": 1,
            "overall_fee": 1251,
        },
        # DEPLOY_ACCOUNT the class declared in the previous transaction
        {
            "gas_consumed": 3096,
            "gas_price": 1,
            "overall_fee": 3096,
        },
    ]


def test_deploy_newly_declared_sierra_account():
    con = inmemory_with_tables()

    cur = con.execute("BEGIN")

    (
        dummy_account_contract_address,
        sierra_contract_address,
    ) = setup_dummy_account_and_sierra_contract(cur)

    con.commit()

    sierra_class_definition_path = test_relative_path("./sierra_account.json.zst")

    with zstandard.open(sierra_class_definition_path, "rb") as file:
        # class_definition = file.read()
        # class_definition = zstandard.decompress(class_definition).decode("utf-8")
        class_definition = ContractClass.loads(file.read())

    # from starkware.starknet.core.os.contract_class.class_hash import compute_class_hash
    # class_hash = compute_class_hash(class_definition)
    class_hash = 0x4A31654529891920D9A6F69696A23A2916B9780F830D90E452E2FA90FC9E715

    # from starkware.starknet.core.os.contract_class.compiled_class_hash import (
    #     compute_compiled_class_hash,
    # )
    # from starkware.starknet.services.api.contract_class.contract_class_utils import (
    #    compile_contract_class,
    # )
    # compiled_class = compile_contract_class(
    #     class_definition, allowed_libfuncs_list_name="experimental_v0.1.0"
    # )
    # compiled_class_hash = compute_compiled_class_hash(compiled_class)
    compiled_class_hash = (
        0x5B7768D97325383C91E372E47E4E7C394F1483D97445DDDC72F56E59202D1BC
    )

    con.execute("BEGIN")

    command = EstimateFee(
        at_block="latest",
        chain=call.Chain.TESTNET,
        gas_price=1,
        pending_updates={},
        pending_deployed=[],
        pending_nonces={},
        pending_timestamp=0,
        transactions=[
            # DECLARE an account contract class
            Declare(
                version=0x100000000000000000000000000000002,
                max_fee=0,
                signature=[],
                nonce=0,
                contract_class=class_definition,
                compiled_class_hash=compiled_class_hash,
                sender_address=dummy_account_contract_address,
            ),
            # DEPLOY_ACCOUNT the class declared in the previous transaction
            DeployAccount(
                class_hash=class_hash,
                contract_address_salt=0,
                constructor_calldata=[0],
                version=0x100000000000000000000000000000001,
                nonce=0,
                max_fee=0,
                signature=[],
            ),
        ],
    )

    (verb, output, _timings) = loop_inner(con, command)

    assert output == [
        # DECLARE an account contract class
        {
            "gas_consumed": 1251,
            "gas_price": 1,
            "overall_fee": 1251,
        },
        # DEPLOY_ACCOUNT the class declared in the previous transaction
        {
            "gas_consumed": 3098,
            "gas_price": 1,
            "overall_fee": 3098,
        },
    ]


def declare_class(cur: sqlite3.Cursor, class_hash: int, class_definition_path: str):
    with open(class_definition_path, "rb") as f:
        contract_definition = f.read()

        cur.execute(
            "insert into class_definitions (hash, definition) values (?, ?)",
            [
                felt_to_bytes(class_hash),
                contract_definition,
            ],
        )


def add_casm_definition(
    cur: sqlite3.Cursor,
    class_hash: int,
    compiled_class_hash: int,
    compiler_version: str,
    compiled_class_definition_path: str,
):
    with open(compiled_class_definition_path, "rb") as f:
        contract_definition = f.read()

        res = cur.execute(
            "select id from casm_compiler_versions where version = ?",
            [compiler_version],
        )
        row = res.fetchone()
        if row is None:
            cur.execute(
                "insert into casm_compiler_versions (version) values (?)",
                [compiler_version],
            )
            version_id = cur.lastrowid
        else:
            version_id = res.fetchone()[0]

        cur.execute(
            "insert into casm_definitions (hash, compiled_class_hash, definition, compiler_version_id) values (?, ?, ?, ?)",
            [
                felt_to_bytes(class_hash),
                felt_to_bytes(compiled_class_hash),
                contract_definition,
                version_id,
            ],
        )

        leaf_hash = calculate_class_commitment_leaf(compiled_class_hash)

        cur.execute(
            "insert into class_commitment_leaves (hash, compiled_class_hash) VALUES (?, ?) on conflict do nothing",
            [felt_to_bytes(leaf_hash), felt_to_bytes(compiled_class_hash)],
        )


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
            sender_address=45915111574649954983606422480229741823594314537836586888051448850027079668,
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


def test_simulate_transaction_succeeds():
    con = inmemory_with_tables()

    con.execute("BEGIN")
    con.execute(
        "insert into class_definitions (hash, definition) values (?, ?)",
        [
            bytes.fromhex("02b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513"),
            bytes.fromhex(
                "28b52ffda0918a0100352d013a01552c33c0668a881b70e2ea6854bd15835ad5cb7577b049bd13c48060e3141e082c04b0ca44494999037514dee20adc24088220088e07f702a802d0024d997bfdbbe6165bef8bb17fd5f6babe5cfffa9600030161c0b6f532776ddc9aad5fed9bbac5dcf9b66fe7bc96f999fb36e7da3d5bcdfeeebbd9abf7ea3af62bc104b2e0d1c041e4e198405518241c5042394152d3a3824f83634e09e113e5c49bb3a9f41449f1915372d024245495297ad84a78104a032aa83225e594051c4088a38a1e6962a09c7e8a8090a6240b0bc6d2b8b090f3a9a89e05900792094422f228c001495233e79c73ce39d9b3a41c73eb652a4939f69b73ad4bbf7594602419262e8da5b12c2c8dc63e29394d8faa602e9c879213e69c7356c888b173f96c4d560f55c1787c9292138f922a0a2545bccafa2be19be6c5042992d2b427331f68227a26335564f5aa09bde871188baa7952b29acf84a42626468f991c4a5672a2d992aa963392a629a9555e361f889207602812e530cebc955b859aab15f299a0ec40723217502451548f02bdca0292a9a488a92839e7831204bd0b2981810fd45426a682de64e694548c8fa9e0a3aa486a7517123451cc47c1ccf9a07d6fea415046757ef181de845681de84c8832122c2141001318083c4133d8e8ccc01044b6359a8246580aa5452d24b55d3bc98d5031f68a23820d0c7cc09eae18051c589c0a82a535591988a47bd88929585644090aa474950ba8713c3c8aa02a58564184955aa174d3c12137aaa8a237a20394df2004c2427c97151516f6222f5505410110e13868704c443326112702800227130abe85533922a19494840240d0d0f06c2818183246249cfa4e404c6d290d2612c1e05c19c555491207cfe5450e561be077a4c24512812743824f52a24502f929eea454f351750ccd7e0e251d40356a86a329606e5450c04559c0a0c04cd91849857bd08410f2e25555042723296460546054987315d548c443d0f3296862e0b8c4a4ec791a4aaa1480a6369ac6581210ff04c087a0c0e86899e47611806054a3ece5345323e8ca51181f1668452029414909113d1a3184b8311c949c928270684658131a3a7829e4ac3581a105489960586e4440f33516964645058161894474d48d4c4a010ae1deb6f471400e1c02430f165cbb9e3e6dadab5f5d7b96ddeddd42d0304e4010120124d951bbb5dccf4b557dfedaf75cbb5296b77cb2db35e8c759bb35f6d6dcb79add55edbf5b69740d877fddf9fddb77f6ff6e5c61a33ee6f750e1e1e1309c883c344597d35ebb75eabdaecde8de9baa66dad5df0f0008231802122b2809940185c4809919c00a91e0aa4ad77ebbd5bdbe96be385801c0061260e0f1004abed8bb781b96daccb1b5baceccfbccf58db75dfac395e8db9ff625f8ddfb1365f5dcfbd96ed33b7cd8d29f772fe6c97814c1e0c201148832e86519754535616901403043d6eabfdba656df12f65f65ffddcde24111306480422c14c181e920944040313893c181a469d99330f9089030361f090444c2498041e0fae2db7cf1a2fd5f5fdeab8b57db9555e4dd99be3f77e5f75f74c374103c48388050cafeb756bd9f2d58c9dae4b2091068847036623bfceddcbb7d939c4808803201c7ad731d3d5586bdd65e766cfcedc7db5366fbfccfd3fb3d609c4830806860753808888036fadb93b6b7fd79c1b330d241e0d1888e411618034c0c9e19ef3002f02582240f8a5d138f04de7f20b869213242829c8441263c1cca7a94ca84281b279200725a1679a881e34bde57091841cd35bee8b49828cac448fa43caa0048cd6a76d3546044681c58090c2c025826c740351f84c0982a1235c14c448f04667a0c0a124692928ea4de6b1e6bff8cb9afd5cd73a7ce4691d5d37697062b2f0bec1cab21d93cc8274982a8ca420f4a914992220c3d8a6a42d74e444f8c6f62a48899cc8c9454c144552429aa022ba85289cf9414135f6501289b6bcbd779af7373ceab6e9b2e3b755fd66c356be624900649c4eb5ad69cdd9997e3d5db7429af5ddade6d39def6eefede58d36e6d7d5fd93d638c7d0bc0ca98b6c61abf6e5bdc7a7db72db7b8db5f597b768b750b76c3cff1fa66cbf8d74be6b05e9041b6acb97154327d2d2e6e2baa42e7698bccda8c5b5ce838dfaa4b3ace374d792dd4719cdf65a10c080b8ca5b13496c6d2581a4b8392132f7a146675579b853ed4e4d8752883895021c2daf7c6ef18f35d4d1babffd276dcdc6c6bf13b3b66f4ee3c309746c3d178ee2e8d5e670c8aea2958140060813c38481c2c01580e2458087054681a15282c0b937a0922295a16a2849ee72c04380a28b034164a5a22050e340a142c1632460fe358962552c0c0a2a089d15b0e54d1b3349e01099ff92c0a1686a2929a4881032494679150f3aa072548520eca84dd666938a6db9a7bf68d3d7b776cb17bfb5a1a8cf828581a0a0cc4e851ac65eeeab160ad8b9c905c7419c0122dceb3eca2608914d845418225f255ae30e3b32c10101140c10025ab48329409acbc11627c923221e7a26089303d081794449114d52a7a281cba5494344d95b94c29c56559f8174a525452f49625ca66a9a4287a7059e64331591c4be458dd62b71a4c184040220d0e91c701100e8c0adb1c1fa642829c2ac2d2604c129c8c849a674ee9db0c255194ac2acd4355d57b3c306d02e1f08059dd575bcc7e5ff5b7b5e75fab3d73bfd829dbb5d82f67beefaa87aa90d54355c8eaa12a64f550155b3d54c57eaf66cdda2b8265e1dd337fc6cdce1673aef9f2f6eddf78ee5d1a1556f3f2c3488a587c28fccde85115b3345af55008f0d278280498e393128e4f822ede2455f3426223d2e42146b2df31634c5dd73756ff854c1c24087053a6dfed98baa6daf08048f4ff7bb1f3c6dcbe3ad7abb51b8b984848401e98060888c48318247cd024258c69fbeeb57eb975a9baf323c2c040181e110710c905f5a8e651c6f677f5b9977bc6cabe99395bb6163766b7feeeaebd3aebff2e7ff6d5cdac5701240fc9028788840402078bc98491c48392d54479d59494671231cd56202440095a50c977affacfccf6f7d7abb2c610c983c90382818344b3b62eef2e650d15222088302b64c49892baa81ee8695e5579e0ad9ee6b96becde6bce5387dff5636e5e7cf81cf864d3d8f9bf95cebbb9f66acc45c8d469a0c3bad539cbb13bb171ab4ec31e2b3fd72084b0697039f72d77f1b673c3eedc719665cb66af69a263bbfee337ff3442f6b8dd157e336770c1c8ccc9c5bfd0996c5c7b2d2e5f199d7237cddc6a228c4d753da71d8bf2c1c84bea8a2f9bdce61b5f749a079daeee06637bedf945a7bfcb693f6d6ee3e3b5fb8e6c22ef7272c5e510c2f5f52a65944d6c9a6e20db6ded98b5e6bca3722973b856bf668ecddebd0c5b8cb161df513eb96b9de5f8b6bb94ab3ff673d3db38feba1ffa73fddd6c1be750d98a31be74ec5cd334fc06ca26325e57b99af37eecff0f5d746db951c7d1765654b9cc7235caa07b0cdb791d9b74d69b375faffb45661d9b94cfcc9b74f89ac639d261ae8d7bb1b16c78c96d5d8e367cfc208bfd7445dfc8034202992400596e1d36fbefb964ef2ae332f3c7fa9a39eb3de774a97bbfb2dd3dc6eca8e334080f24130988080606858b869917541549b89ad790bb31b7aa7b6dbdc5ebd83d08217b2961e4d62c6373ad890e7f95a9f3eaa6e38b6c75df920e6bdd9e9b31cbb8d65a6ecf1e7bedef39289bad6ef449d9c0b878a5765b721763bcecdab7e31e741eebbae63ddee5c8c60b1feb869d32f68c7993517af39cf5de1d6712767b749e37aafa7677f56a0d4b07bd35cd7271dd39838ea31d9be840e89a666d4ef37a5565b7d5746f74d8bc43e85c830d6cd6b1aeed7dcaed3db96df5b5d15d86cf4cd9b1c31893ccadf6cbb971b6de31fe871042b6cc19bbb377d8fa7656d6dfef6cb15dfcced63bfbe69ac3e6b9e6de6190e93b5bccdf058a77a8f4b40ad4a8534a313203c0089000f3110000282c44994c4a8b9cc77a14000e151314110c0d0f0c0e0e0c09090909070b090a08050987c3216128140e88848121796c36e9e478006d0a19b1f8c66d8ff377368cfe7ad5d5d2a0feee70d21786d3b0435475448db1040cc9dd93356ef0ab578011db0985c68a1a19df875c5e20f56594748a38b89571537371f3a6c77abdf6fc5cd97ee4fdb1a65f87c9e71bad54a899955d2385a74de7fc7e3fd3d57b1dd55789183b61a0323e2abd46caa3c487c3a4f0dd49c30d22d5ed4bf38804dd8025cc69122e42f6dd71aabf1fed08300b69a832f40db1411149eedd27705e833ad8883c2dbadb5f22e2f3d18360de169cf6a2f305720d3ac0268c68814ca72f51666de859b13d8113034d7700b50eac9b6099298df085bb6d5284ca1be204d8f32bb50ad1e80e139271e1f075d84e0ca3c64b283448daad10795104cbc2e559d798bd1d7cd84fcc19b41902c6e2433fa5880289f15f07fb2defc5ce76316daedeac0684150868e98097106d4006e0687918cbf5b80dac2e5255a3d43549b9b09723b31a4527e1b2f67a4511e8de72791406d6fb804dad7db99b2004bb449e143e15d179f901b28410f287c00cb12180f9d93850f602a4aa6d8a9d6035c8a95f752a8148976eae7bdcb1affdbd49c1baa77d0926213a2905df9f3c0ecb7252a1d45ee1913f8d16f35995f7d0cab8fa8bcdf74173294058a5fcdd06efc01959eb296e7bd4a15500b18d3cd88bec0cc0fea0f29c8069172066a1159bb5b3643edd3ec6890dc43a1cc323c3b95776ca42234954c7d26ca1fb9880c6437664276f04e3565a251dfa9eb11d85b86eb371b0a04141933f902438ee8f3aedb48bae5141886b43dc03c7e4979fedf19c604b21a099b9dde1474848210fe8b774a48b1fd6811d54d4ae3615784545f8bfa48b49e8c316d03d2e11cc7a0bc8ced911a39fd5d8d1baf5a1f2cc6273d333669c3b6b53f81aaf9aeccce303e4a4a28abbf57fd58438561221fc735eeb65bf24e4c005b83e6ae6b8dfe20e206e3896bb499fb9774584c10ea456800c4c265c2c9883808a0d528ca89128f68c7fe1b81d4a420fa099d0023aa9071a470d9757845678a8d6da53951398d5a35938e1c528de0feed80df610517aa39d8ef8968f3b4116affb4d3850a5e7004eab3448ae0c22a0e78582f7262171420105ddca557c8ffe6dc5a4e445f1c4a8411839beb3e3853e725e9f160b4c3dd029ffa1b437574afdab8141456b3087158a0eb4d3c1ac5353ad9b1edef09bf0ecdc16301811b6902669e1ecd9087d099c865683c13535ef00c21be5446ad5a9c79352b67761972fbde959f22eb30afa881f78d7c59bb8d61ec483ac39f146453af1eef3945fdc15a9824fe081291c4394661118c670fb7732db3890803846a424ddfa4ea989955a43641fec003771d54a14881eaad2d0841333390c02b7165f23e0c051cc200253624e90a6066073c9afa317e071df8d13061839f2edc87858884eda7a6e2fa6fa4b00f762c14c5e003e596341a0af186e8f0d637f6eb91e7f9ba3a419751040282a4c39f0a02e232a05fc8d00404c73d148e926b6d15cb19e14a1cf717049207ca640164813a603b72ac37f382e9656b691cfa09e8560a9ae00908c1d3be121eda55249bf16c4fbd34e7853d4950876fe5e2a5f16ef8a8878d8eceea0cde8c228f3867b0b497dd56c45c5bdf80123dec8b36e9cf181af54b77bd9f6d54afe871462a24c8270d84ef404fdde6030db1479f3c80290bbd3515348a089ae38d98c91f5cabb3dae011b504e3633b3da0b2727e4f35241ea153ddd716ec2f05583e1bfd7c27a921c13d8ce6c5651958b69c29af05f9892df79c3371729fd3d4451f6004eecddf2c35b0958415f049c71f9b44e0fbaf9c953d217cb5054d4ac4ee7263f9b5f8331edc59a260651c492eee241f88191d581ebad857c0a6c8f030cfefe452460f07c6cd441c4c0be26379e9290e083e188e74d6ae8b8207e1e09f688919c34e0dd406de204074f8fbbb9f1eb0c6039cf20cd2d2c19e38854c44044c46cdd74cda32c24b79ad0cdf7c6af7a578e0b0384aee1370f034f8e917e2c3bc883adc34c9a8474c89c204c52bce0aa2a089c088199af8da9802703df10e11f06c7c9049c82f81fb2485a8265610d47e57d7814ca1f41d4421ca73f6cb3c19ee875f988708f0119512c7e2d6858145bebb0ca73006779be7256feaf43e310a5dfbe962a79871ccde3ac2c1eab8fb27ffd7d16fd4ed0fa3209d25bd76f7509813ca30cf34d58e8e5ad7684276fc2ec285f0bd51ccbc5f7693570539e4dd572faeb1b6a2825ee96f8b93601f916df219da105026bdc04af0e3baa1e28a754b867ec7a275abc9612d3dfa04baeb91b2674d3068693b19de8480aef7a2a222bf9bfb147af91b62d34d150cb6ef073a9d7416146e7d0132c5f1a876601aacf0a8049011e88810c934b925de44c2bd4c1f3560db4189de4fdad70603a591a48ce3cfdd866288dccbcb71dc5d13c2eb74b66ca976b5fe394b4a90418358bec3fa3b088d15e3e753d04d169db11c48ed8df1cc7e9ae461a19c34b316307cb97a7fecfd1240d32f34099f9f01631b82e7aac4c6c03806def12de1900207d8668b37442ed8635e92254d6d3cc5edc652e9f35c6eb78eb3596e62ca6c6a3ce3b8ce00f52ae465945fab4f3dec6fb7a7e718c229843ad7243f80805895f93ad88a219daa4fda2a726eac8bd29176972316e76a73411466d510c13503a966cfad9a634103a1753e7100d5f2cc91606cf16a1f67d81c38a603977d07b2d4045a85a45c2f323864fc222440e25abf3be60365b1441b93e5ccbe923ba07244c0e48dd6b86568877bcfe537ebb241ed0310c20afdf4f258d84fedb415f96f1e1dc4e5256263157d76106894bbd4721ee432c180a89c22a11076f0e7245748ad3442b3606139850bc8640f7d748df30f92f76cb33848d71455d2b12d329443c1501777d27d245fcd170c48b4ee21decb20141071914114d78caba00f677fee6c3f8f40f53d9c35477e454172b4fc5e9da2ecc17ea72a8f5b97d47cf390f8cd2e8d1bc38e289f988aeba47cc845198ad0cac43ee70a01c72c54a08b4b37b30e3d2c0796f96e780b5c9d741f3932824a06ad3c7bd2d8b214fa91d184d1511bc45e8a2f6c4552201b26b3a6f3f519a7ade1ccca22f7f9f44bd700a84eb56d842bf3754c965bd264238cde178332796f26604d966ce37c013e2d497212bf6972741ee4725dcdca0954fb5d5a19b900514c97fa94430ab845634047e0143b68c233149e6fa85110a07fbf28ea4602fbd7e55ae09418c175136c68a492966cf1231ff81614c200669d5d185a873f474124ae8052d2b1d4f026e8edb9dbca4ec9448047f15b8f989d63caae417a71ea244623c0426419ad79d4bc474c5a54bc4c4cd799258e002b1d37939c222707aebd35d47412d94537a48ade06888ab27adec24b66c86d1498af10ec8cac2c48b8d8012ab91252d20d9eb93f392a7c1522411a446de6f3a363f28916b2ef4799fa858a6483a2f7aa9540b3c1bf1ac89b06b0752640ae112a7b72b6d31789d56b454c4383cbe44ba011099f40a61059c551b6c74ebbf864a58b8f99bd240219fb3879c505030c450840c41ae5b878748c9d8364e985893ce0223c5461c0f905ab37505a9655f134986166a944be599af9ae9082046a2b908aa5bb010a6ffd7f24d1c4cc1c658145a4b184b48ac3a42154a4b627709e042d12fcba9be9796fd8249bd880c2bd260545a2994ca00c417e95a79ffe4e1eb0f544c310cbd4a2a6f11dd37245df2d136a40c7cb9da8491dd6494a930aa78f37564549e7d1095c2d00e5af2aa5f5a49a30b80d4b972af6b048a9af74644f3e73ed48f48a73b8fbcdbd32323b1d81f45cf4163d9c7c9b6a9e1e9b4586a3526edf661e5d03caa883ea4b9396f92d0d4a4832a04462f953b0a7b3fcd0684af15f2eafc324bda91401ce6108e52a698d50038fc20dfe7317f3b1d6bcd41822246eb716c1c6b25a73f42ac308436977a70ea0e318c4854f5249bce07772b48040dbd856d52d19f5b6cfc63a1088edd65d38317a5c56c837e563944e8ebe94123196cfc0b05d081c055bed3c0ec823421038dcf3fb0ed6a57ef02cae14389df0087e39cc69d45b8a24131f18a7b0d38f97096c66d0bdef59dcb957a4f381c26a11fa8ec853b1b40c5b976fba1030a1042809bb042e5a3378b6579ed75472566c59718fd309736ed3d346283fe21ba338c412d442ad1a1eee64090853d87883cddd121a231ba7ec9edda372d870f2a6051ea13032db7af14f64eae5a9ad5b62a72b6c0b6601a2dfd81fb2984591a640adb51cb1696ebea048d34ceacfcbb85cc81a94ae0da6bc49eda4299a18cec29fa8633ce4ed62c22425084cc94c2012a37fc78048a276e5b48fed86a18092fd47c7aaef48c432655376e6e2a62d9377405f916b2ad89febb2533c26cd7ae856587fb96f8865b616c3a0951bea9c4b0145ac107b6264f204fd592773ac0eba4ecba2977bc6975a56d6f340c0c56fb08d81f4dbf528360df11aad85db2734af723e082a927817745be8cc54e6d4cf78e095e807a6778fbbafc2995918ab8a988e4bf0255ad72ba36f7a50355452cf3955cd2f5a954ae45cff05024cd3f3e7c31ed184ab8ea65a04deb6c63f5d43e016e54bc166a3c097a7299b939e779b93d9cc4bd7b1f2a74c49f167fec1bfa8cf22dd5ba1968ea9a75d49daf62dd19a6fd54171d3ef8a0fc0d9e1c42200daca49c8baf48194ab73ce8919e33e62ac74730988c6d1f0571dc3861c30576be164d5209cb83b14e7cce701ffcc74fcc1377d2d0a29f84d6243fc71318a1e8a0ffce7f3b36bd12f0ce7d9a227dc6d19c9526497c640f46f0a5c6a8c78e72f802a78ab2980558438c16199b3562cebc6f0b35aacd20e98ae05a4184c6553385de4a4c26b0bcac520269bfdcf21b9dfff502f7fdf6379f4e36bc299c1b6623de10aa7753b5e78b2b854455e409d0ea4acf29cb418cf280091cd3ff5ad928437fe2d37f54900597a000808d058c0ade5872204db16d76c561bb22a39f02f6bb72d8bac5690cb957b61fd8ff8fa3da1bc65e218723a3c6c47bcb372a036baf248fc7950347e6e360a6634b8f0d2a48c6383fac615b63905182f879d0510a5b7bf6c91a5aa4125e1ed3dc7613ec3d9fd03254ea4c52f75bdb990f89961745bec39eabe67cbd045bd1a5021a305e2168d7d25e4df671e2f7ac4194df00506c41ba9de874181af5531dfd4cc0d395b64f95490f1a35f493505cb26ff012f50496bae18ec5dad8bff6bdd5257b86c22db0f313bb4368da75255a885da2d1546b02da6213f9d1d1a7f837740551fa7086c8765b0088c2b196ae61bd5117662ff685b486d156b12b2285dc25ecd79850813b8a2fbe470b6e9c1e4d48abb761f507043cba125f718782c2fb4db090df03c51d6dc5785f284bcbc624135639d14047692e6d7f9c7f239fc124fa0c5635d45c37254fedca8cb61b8eddf6c80d6e4c4db18282f885179cdbcd8cd75a2b0f904eb3d83a20640ad8b25badf703b1e44866adaa73d9c4a3778439ac045e975ba618e08c5b9fa3f8cad0b73abd2bdaa5b98f3041dede123fc8c41db668c979b27fba370dfa8bf073f4889558c8db8825788d879e1dfb40a26a47be2866610c269a2d1466109ea7f20d55d1708762a7568626ab34304f88a487c691ea07c7a009479af0acc149efcb04e486cc4e90e03cf644219edcf64dc63b5615884f5bf36a2de7056ce02eaaff90bc2b4d79a50be461db3cfcedc5214b518e830fec0437f51e246fff186112631579adc774c09e14f40f6b64d74748c6376753d57a4a15a05683735d90d460f15860cc1d121acfb65238e1757ab64b8b00b7b32eb8cf5f271624c9b56823be918655658c2582f88f453020b3a966a7b9575ba665abd042679f376b8cfc24e9ac413047ba2664925ba2438e198207d9530c645b37fe2250010e18140fd396f9e27a19c02dfb5e3b6b9b4e175d35a794bc6d95f4d618970daf6c4b5c77b8d17173e7f74c93d9738445b04c1ab9e456ee6e4729c836785288a046e115238f2720d09312c4e9412e924f59256062b4a1c6020cb6171c1b520289bcd5acc85277194bbad4ccfc7b7e374900ad5672a5695b922deb8fd7a45aee363fd9cfcfc24c4d51f63fb05401f51575e31ff3be719126a3c69c9c88985ed0b446b2b475227d30983759064241c84d0966ff593ebf2a2141e86625899f0bbce953bd8a49871c9732d122c9dbd4395373cfcc2b75e24ef7532f7aba2631ee5993b4de94497279ca9de25a5572d2d93843c65807d6a9335e2ea801ef81a281ed91c28a1f9c5982c2325dfed3564ae5556be86d6896215dba138d15b62cd1156348c85080c7812fdc0c5c78e12a0a8ef9e391950c9953ccdcb2722e44bf2b1587026d3de8b5a5ab2f0e115cbb56b6d2cd84025f0ba68e0f90c85580c4d0890cc19486ec18fac4b003ea84b9e493718d6bff42e3146315a1de7231582125f4cab6cf49c277eb1907e508c93db4d0edf306cffd2a891adab3b9acd4150b3d574423e2072516f7d304ec64e4cba2a3c31d0e80c9bcc89c14d8de201e04e2d9a22eac5f0bcd39e0859cc210c3ecd92061f991913e0b516d09cb1deb4c28382caea369324850584861d0e706b211f22de82b00308e84cb07aaec6f84f56eb26843365034c343b7c63538b7c9f918492d7b4531fd5ba619ffbec175fdcb077a07c47132f1c37a1684c226e3e85820b2e663995e8100fe241b3e02a3e492ea76ea0c1c38000f221d22cb0b813e3743d59777d79c3a255cd58ddfee0594af3aad877d03a2146955d9f685a67b49d7d238c4d8b866e2fd9b2a859e997a80fdd3781f1556a86e3f82048e5e1eb0b852cd068b15959b80af9cd691bb4a930590fe06fa50194ee2a11bb5c1208cedb6081baac5b6f3242d333369066badc746cbe8c1f4145529b630b340d4ad14e7290a4506a93a62cfbae11b5925f4112ccc11a3661bb59a28dec26bb7acbf25a46ed5ebf26a292f0fc0dbf68322fa1fce8eaaebcd4bdcd601822cc018d49168b46e111d055064b3748b2bb002f38d3ae09a3cb24704366b35771bd06218c1cfd0d369afc93dad679d8af090c3e20f663956ee522a7badd26d53937af3d89aba4301fd8752b610bab9416d16d5383e68ab375945bf198eed42f2450cf6b58be1193cac8848a90bbf814ba760656cf0ed71bb47cefed86b679229d016b4406ce0fa468df6574afcfdb9c711ca7deb9aecc0bd1051a7c2427ba7f9a8a4747045eac79aea5baa0695615872c6a91dbc5822b3ee9daa5cb4d521e32ad3d85b09ba28ae39ffe46afc51eaef2ad1b043f763aae01b2712872692b0a8a0f8fec9d00ad6c884582d37b065daa5aff49fe4c99b4a10d6e3335eac87a2fc27a583699a3b4df200dd37a1bd9f96b55873d1f0fac756c600fff610d5b4996cc1dbfe37413febc6d0de1f313bb4bd03ad75ae7cdb8bde88871a02c8b82cfe838db62bf95b7fc9e2a401f6f1ae5149976c7ed11ca867951988c13287869c5d2b599947d2f8facf899291e2567d57bedc73fef03afd18f1db185a68db7bf67d09903111b8d111132af34c1d66148daa3bfc546dd03b4f906c2443c5fd9772fc3be5f3d10fb593dad660945f9aff14edcd2fda59006043f57a22af6d8700d43f600784df3f0157fd8abb96b9fed6000a9a32f680f30c74e21a81d811866b2a67f80da848e720533b00fdd7e3606e8037bd06906359df22facaa70d9a64c60caf043e2a620e15e3c6cff340c3d3daeed54c50288e93046deb01a6e57c1792cd1f6cf4f9d8a4b055ec627b2d9f336a3e3af439fbd708a934d933e8ef44e797bf279b5ba95b72cd0cacb95211298e748e69b93849cc564d9ddf2ef10567a638732eacee3eb960d4760f21adf09bf5088a11ef4dffce3a3dd31c4fcaa3169af889bca315db499173d6118ce8a892d115501d94702e0597ea80ce792907693544bf728970883b84c4b895558c090d94f6c84ad8fd5a8c2dcf2823b0b28cfcfb82feeb38514c14726e250b367efa1217d84ea63b51f171ec707cae8317675f3dd32ce99a91e2e6be526cab89269101ed97ed61f15243e47afab5bd72fdc6dc88d9127769e6fc9781e72b942729f45cbab57e5cfda8e0213663f0526a2088d8441728aa26b3941471b5ab23c90c294c38966d62568ff12e2a66ced08916a224468dfde73693befe8a1fd0f1081b33491127ce0a551b7c57c9e56ee6e4b02d83c10fb3074867dc31438d580d23931c8203aefbad34220c12021c606ead50e048d5c9802aca267160babd2e041e40180f248d5e43e3615922d61a37f9597f23b81b0fdbd57cb82ce8f195d33631dfbab8d2d70f708f0978b089febd76a2368443b80781329377d70d6fdbe9a9a5fe55ca080bf54e3e05a5b235cc7a7aa91afe7f84aabb50bf37ce854e48ff61b86fd56dbee5e85f38dc18e25e9bc2c8f0e9c42e8cd69c188e5c2ce7d612de05f07118e5b766b8ce74afefc9c834e678621952fe5504b940793eeb580e654e3f7810136db6f533166708355e6eee313352e583aefc0f1b22d6660b969d9965317bf193cdc2da4d870d3385c85873f99f17d7bfa156bd7913d811da2368b427701ff7e4c1cb3d53eb9f51a54366811618df679bd97e1b52837bfaf1725ddde736fdd1173bab5c17d477d7cbb0c143e898f1072f75f72638a7f8c7298d71851f47c674dd8b91f4447cd174649814f57aa99c45dd961be3a52a1754806f58fb2d619a11f8e0d4bd4d07ac35fd248baff4dc259105472755cd5aebcf99ebd3f908dbe97ad2567329995b8c47e856e9a7f1e678520975e6d837d44c555907a159d837c8981af3a3002db05e8c8a8218007f43a8474f672fb280df312b8d6c6f128822f9f7b4b09201bddc72e0b09477e984ac0a0e3cd740cb79ff30e69de909920578b87ef4f672fbd3582ed245a2fcf0db7e7ff682e05c2a70d043dac94d290a2e2d5d10d5100707a13bc27ae27d141bcbd12c58619aa7329e9b4f2ee978cb3a0b8e026b0f7c813f01f081e250af9675eb801082fd7f360a2cff7d83b0bbdee109af67ce03d52924ca683ae97e171ca0cbfab9417b3afc488168e440321893b2fdf823e096fa0af07d9d3db22d94bee9219f9e9cb9643b323f6b9abf6963f7f42023662beeb42e376dad3bc9212660dbe9aa93f036b3b62fc90049b6407e2c0d88d12da15c0511b8576926c239b537e9678010f1cdf110aadeb4c5ae1e52410accd4b1a0086785f98ac52e6b8cee557588f59ce7dd61785e61ea6697376d5e16771bfef2cb7c6eebc99fbdd04d565bf626ec956b6eaeb3a3a901f63d673f8c4e286cb4e40e0dc65d092abc6156118c7b727ab58cf4e8946fdc7857a8290337af23e47046462d0cfa064e0f3b6feb70b334d4142100c82669430aab289734c3f288f023ab492a0f4f3b2f4d298a7e6ca3ed1ab241f348b3435ce1e0ba5a8dd90d34a96ef944803ddbbfc0e80fcbc0df104f03f703"
            )
        ],
    )
    con.execute(
        """insert into starknet_blocks (hash, number, timestamp, root, gas_price, sequencer_address, class_commitment) values (?, 1, 1, ?, ?, ?, ?)""",
        [
            b"some blockhash somewhere".rjust(32, b"\x00"),
            b"\x00" * 32,
            b"\x00" * 16,
            b"\x00" * 32,
            b"\x00" * 32,
        ],
    )
    con.commit()

    json = """
    {
        "verb": "SIMULATE_TX",
        "at_block": "latest",
        "chain": "TESTNET",
        "pending_updates": {},
        "pending_deployed": [],
        "pending_nonces": {},
        "pending_timestamp": 42,
        "gas_price": "0x1",
        "transactions": [
            {
                "contract_address_salt": "0x46c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                "max_fee": "0x0",
                "signature": [
                    "0x296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
                    "0x4e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
                ],
                "class_hash": "0x2b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                "nonce": "0x0",
                "version": "0x100000000000000000000000000000001",
                "constructor_calldata": [
                    "0x63c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                ],
                "type": "DEPLOY_ACCOUNT"
            }
        ],
        "skip_validate": false
    }
    """

    command = Command.Schema().loads(json)

    con.execute("BEGIN")

    (verb, output, _timings) = loop_inner(con, command)

    json = """
    {
        "trace": {
            "validate_invocation": {
                "caller_address": "0x0",
                "contract_address": "0x0332141f07b2081e840cd12f62fb161606a24d1d81d54549cd5fb2ed419db415",
                "calldata": [
                    "0x02b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                    "0x046c0d4abf0192a788aca261e58d7031576f7d8ea5229f452b0f23e691dd5971",
                    "0x063c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                ],
                "call_type": "CALL",
                "class_hash": "0x02b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                "selector": "0x036fcbf06cd96843058359e1a75928beacfac10727dab22a3972f0af8aa92895",
                "entry_point_type": "EXTERNAL",
                "result": [],
                "internal_calls": [],
                "events": [],
                "messages": [],
                "execution_resources": {
                    "n_steps": 75,
                    "builtin_instance_counter": {
                        "ecdsa_builtin": 1
                    },
                    "n_memory_holes": 0
                }
            },
            "function_invocation": {
                "caller_address": "0x0",
                "contract_address": "0x0332141f07b2081e840cd12f62fb161606a24d1d81d54549cd5fb2ed419db415",
                "calldata": [
                    "0x063c056da088a767a6685ea0126f447681b5bceff5629789b70738bc26b5469d"
                ],
                "call_type": "CALL",
                "class_hash": "0x02b63cad399dd78efbc9938631e74079cbf19c9c08828e820e7606f46b947513",
                "selector": "0x028ffe4ff0f226a9107253e17a904099aa4f63a02a5621de0576e5aa71bc5194",
                "entry_point_type": "CONSTRUCTOR",
                "result": [],
                "internal_calls": [],
                "events": [],
                "messages": [],
                "execution_resources": {
                    "n_steps": 41,
                    "builtin_instance_counter": {},
                    "n_memory_holes": 0
                }
            },
            "fee_transfer_invocation": null,
            "signature": [
                "0x0296ab4b0b7cb0c6929c4fb1e04b782511dffb049f72a90efe5d53f0515eab88",
                "0x04e80d8bb98a9baf47f6f0459c2329a5401538576e76436acaf5f56c573c7d77"
            ]
        },
        "fee_estimation": {
            "gas_usage": 4323,
            "gas_price": 1,
            "overall_fee": 4323,
            "unit": "wei"
        }
    }
    """

    expected = TransactionSimulationInfo.Schema().loads(json)

    assert output == [expected]

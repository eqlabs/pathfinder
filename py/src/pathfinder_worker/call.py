import asyncio
import dataclasses
import itertools
import json
import os
import pkg_resources
import re
import sqlite3
import sys
import time
import traceback
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Dict, List, Optional, Type

try:
    import stark_hash_rust
    import starkware.crypto.signature.fast_pedersen_hash

    starkware.crypto.signature.fast_pedersen_hash.pedersen_hash_func = (
        stark_hash_rust.pedersen_hash_func
    )
    starkware.crypto.signature.fast_pedersen_hash.pedersen_hash = (
        stark_hash_rust.pedersen_hash
    )
except ModuleNotFoundError:
    # Monkey-patching with our fast implementation of the Pedersen hash failed.
    # This is not fatal, some operations will be slower this way.
    pass

# import non-standard modules and detect if Python environment is not properly set up
try:
    import marshmallow.exceptions
    import marshmallow_dataclass
    import marshmallow_oneofschema
    import zstandard
    from cachetools import LRUCache
    from marshmallow import Schema
    from marshmallow import fields as mfields
    from services.everest.definitions import fields as everest_fields
    from starkware.cairo.lang.builtins.all_builtins import (
        BITWISE_BUILTIN,
        EC_OP_BUILTIN,
        ECDSA_BUILTIN,
        OUTPUT_BUILTIN,
        PEDERSEN_BUILTIN,
        RANGE_CHECK_BUILTIN,
    )
    from starkware.cairo.lang.vm.crypto import pedersen_hash_func
    from starkware.starknet.business_logic.execution.execute_entry_point import (
        ExecuteEntryPoint,
    )
    from starkware.starknet.business_logic.fact_state.patricia_state import (
        PatriciaStateReader,
    )
    from starkware.starknet.business_logic.fact_state.state import (
        ExecutionResourcesManager,
    )
    from starkware.starknet.business_logic.state.state import BlockInfo, CachedState
    from starkware.starknet.definitions import fields
    from starkware.starknet.definitions.error_codes import StarknetErrorCode
    from starkware.starknet.definitions.general_config import (
        N_STEPS_RESOURCE,
        StarknetChainId,
        StarknetGeneralConfig,
        StarknetOsConfig,
    )
    from starkware.starknet.services.api.contract_class import EntryPointType
    from starkware.starknet.services.api.gateway.transaction import AccountTransaction
    from starkware.starknet.services.utils.sequencer_api_utils import (
        InternalAccountTransactionForSimulate,
    )
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starkware_utils.error_handling import StarkException
    from starkware.storage.storage import FactFetchingContext, Storage

except ModuleNotFoundError:
    print(
        "missing cairo-lang module: please reinstall dependencies to upgrade.",
    )
    sys.exit(1)


# used from tests, and the query which asserts that the schema is of expected version.
EXPECTED_SCHEMA_REVISION = 29
EXPECTED_CAIRO_VERSION = "0.10.3"

# used by the sqlite adapter to communicate "contract state not found, nor was the patricia tree key"
NOT_FOUND_CONTRACT_STATE = b'{"contract_hash": "0000000000000000000000000000000000000000000000000000000000000000", "nonce": "0x0", "storage_commitment_tree": {"height": 251, "root": "0000000000000000000000000000000000000000000000000000000000000000"}}'

# this is set by pathfinder automatically when #[cfg(debug_assertions)]
DEV_MODE = os.environ.get("PATHFINDER_PROFILE") == "dev"


class Verb(Enum):
    CALL = 0
    ESTIMATE_FEE = 1


class Chain(Enum):
    MAINNET = StarknetChainId.MAINNET
    TESTNET = StarknetChainId.TESTNET
    TESTNET2 = StarknetChainId.TESTNET2


felt_metadata = dict(
    marshmallow_field=everest_fields.FeltField.get_marshmallow_field(required=True)
)


@marshmallow_dataclass.dataclass(frozen=True)
class StorageDiff:
    key: int = field(metadata=felt_metadata)
    value: int = field(metadata=felt_metadata)


class_hash_metadata = dict(
    marshmallow_field=fields.ClassHashIntField.get_marshmallow_field(required=True)
)


@marshmallow_dataclass.dataclass(frozen=True)
class DeployedContract:
    address: int = field(metadata=fields.contract_address_metadata)
    contract_hash: int = field(metadata=class_hash_metadata)


pending_updates_metadata = dict(
    marshmallow_field=mfields.Dict(
        keys=fields.L2AddressField.get_marshmallow_field(),
        values=mfields.List(mfields.Nested(StorageDiff.Schema())),
        required=True,
    )
)

pending_deployed_metadata = dict(
    marshmallow_field=mfields.List(
        mfields.Nested(DeployedContract.Schema()), required=True
    )
)

pending_nonces_metadata = dict(
    marshmallow_field=mfields.Dict(
        keys=fields.L2AddressField.get_marshmallow_field(),
        values=fields.NonceField.get_marshmallow_field(),
        required=True,
    )
)


@dataclass(frozen=True)
class Command:
    at_block: str
    chain: Chain

    @property
    @classmethod
    @abstractmethod
    def verb(cls) -> Verb:
        """
        Returns the verb
        """

    @abstractmethod
    def has_pending_data(self):
        pass

    @abstractmethod
    def get_pending_timestamp(self) -> int:
        pass


@marshmallow_dataclass.dataclass(frozen=True)
class Call(Command):
    verb: ClassVar[Verb] = Verb.CALL

    pending_updates: Dict[int, List[StorageDiff]] = field(
        metadata=pending_updates_metadata
    )
    pending_deployed: List[DeployedContract] = field(metadata=pending_deployed_metadata)
    pending_nonces: Dict[int, int] = field(metadata=pending_nonces_metadata)
    pending_timestamp: int = field(metadata=fields.timestamp_metadata)

    contract_address: int = field(metadata=fields.contract_address_metadata)
    calldata: List[int] = field(metadata=fields.call_data_as_hex_metadata)
    entry_point_selector: Optional[int] = field(
        default=None, metadata=fields.optional_entry_point_selector_metadata
    )

    gas_price: int = 0

    def has_pending_data(self):
        return (
            len(self.pending_updates) > 0
            or len(self.pending_deployed) > 0
            or len(self.pending_nonces) > 0
        )

    def get_pending_timestamp(self) -> int:
        return self.pending_timestamp


@marshmallow_dataclass.dataclass(frozen=True)
class EstimateFee(Command):
    verb: ClassVar[Verb] = Verb.ESTIMATE_FEE

    pending_updates: Dict[int, List[StorageDiff]] = field(
        metadata=pending_updates_metadata
    )
    pending_deployed: List[DeployedContract] = field(metadata=pending_deployed_metadata)
    pending_nonces: Dict[int, int] = field(metadata=pending_nonces_metadata)
    pending_timestamp: int = field(metadata=fields.timestamp_metadata)

    # zero means to use the gas price from the current block.
    gas_price: int = field(metadata=fields.gas_price_metadata)

    transaction: AccountTransaction

    def has_pending_data(self):
        return (
            len(self.pending_updates) > 0
            or len(self.pending_deployed) > 0
            or len(self.pending_nonces) > 0
        )

    def get_pending_timestamp(self) -> int:
        return self.pending_timestamp


class CommandSchema(marshmallow_oneofschema.OneOfSchema):
    type_field = "verb"
    type_schemas: Dict[str, Type[Schema]] = {
        Verb.CALL.name: Call.Schema,
        Verb.ESTIMATE_FEE.name: EstimateFee.Schema,
    }

    at_block = mfields.Str()

    def get_obj_type(self, obj):
        return obj.verb.name


Command.Schema = CommandSchema


def main():
    """
    Loops on stdin, reads json commands from lines, outputs single json as a response.
    Starts by outputting "ready"
    """
    if len(sys.argv) != 2:
        print("usage: call.py [sqlite.db]")
        sys.exit(1)
    database_path = sys.argv[1]

    # make sure that regardless of the interesting platform we communicate sanely to pathfinder
    sys.stdin.reconfigure(encoding="utf-8")
    sys.stdout.reconfigure(encoding="utf-8")
    # stderr is only for logging, it's piped to tracing::trace one line at a time
    sys.stderr.reconfigure(encoding="utf-8")

    if not check_cairolang_version():
        print(
            "unexpected cairo-lang version: please reinstall dependencies to upgrade.",
            flush=True,
        )
        sys.exit(1)

    connection_string = f"file:{database_path}?mode=ro"

    with sqlite3.connect(connection_string, uri=True) as connection:
        # this is not a sort of "usual" isolation_level switch with sqlite like
        # read_uncommited or anything like that. instead this asks that the
        # python side doesn't inspect the queries and try to manage autocommit
        # like behaviour around them.
        connection.isolation_level = None

        connection.execute("BEGIN")
        if not check_schema(connection):
            print("unexpected database schema version at start.", flush=True)
            sys.exit(1)
        connection.rollback()

        # whenever communicating with the other process, it's important to flush manually
        # even though "the general wisdom" is to flush on '\n', python seems to only do it
        # if it didn't add the newline to the written out string.
        print("ready", flush=True)
        do_loop(connection, sys.stdin, sys.stdout)


def check_cairolang_version():
    try:
        version = pkg_resources.get_distribution("cairo-lang").version
        return version == EXPECTED_CAIRO_VERSION
    except pkg_resources.DistributionNotFound:
        return False


def do_loop(connection, input_gen, output_file):
    logger = Logger()

    if DEV_MODE:
        logger.warn(
            "dev mode enabled, expect long tracebacks; do not use in production!"
        )

    contract_class_cache = LRUCache(maxsize=128)

    for line in input_gen:
        if line == "" or line.startswith("#"):
            continue

        out = {"status": "ok"}

        started_at = time.time()
        parsed_at = None
        # make the first this available for failed cases
        command = line
        timings = {}

        try:
            command = Command.Schema().loads(line)

            parsed_at = time.time()

            connection.execute("BEGIN")

            [verb, output, inner_timings] = loop_inner(
                connection, command, contract_class_cache
            )

            # this is more backwards compatible dictionary union
            timings = {**timings, **inner_timings}

            out["output"] = render(verb, output)
        except NoSuchBlock:
            out = {"status": "error", "kind": "NO_SUCH_BLOCK"}
        except UnexpectedSchemaVersion:
            out = {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}
        except marshmallow.exceptions.MarshmallowError as exc:
            logger.error(f"Failed to parse command: {exc}")
            out = {"status": "error", "kind": "INVALID_INPUT"}
        except StarkException as exc:
            if exc.code == StarknetErrorCode.UNINITIALIZED_CONTRACT:
                out = {"status": "error", "kind": "NO_SUCH_CONTRACT"}
            elif exc.code == StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT:
                out = {"status": "error", "kind": "INVALID_ENTRY_POINT"}
            else:
                report_failed(logger, command, exc)

                if exc.message:
                    message = exc.message
                    if len(message) > 200:
                        message = message[:197] + "..."
                    exception_message = f"{exc.code}: {message}"
                else:
                    exception_message = str(exc.code)

                out = {"status": "failed", "exception": exception_message}
        except Exception as exc:
            stringified = str(exc)

            if len(stringified) > 200:
                stringified = stringified[:197] + "..."
            report_failed(logger, command, exc)
            out = {"status": "failed", "exception": stringified}
        finally:
            connection.rollback()

            completed_at = time.time()

            if parsed_at is not None and started_at < parsed_at:
                timings["parsing"] = parsed_at - started_at

            if parsed_at is not None and parsed_at < completed_at:
                timings["execution"] = completed_at - parsed_at

            logger.trace(json.dumps(timings))
            print(json.dumps(out), file=output_file, flush=True)


def report_failed(logger, command, e):
    logger.trace(f"{command}")
    # we cannot log errors at higher than info, which is the default level, to
    # allow opting in to these and not forcing them on everyone
    if DEV_MODE:
        strs = traceback.format_exception(type(e), e, e.__traceback__)
        logger.debug("".join(strs))
    else:
        logger.debug(str(e))


def loop_inner(connection, command: Command, contract_class_cache=None):

    if not check_schema(connection):
        raise UnexpectedSchemaVersion

    # for easier test setup we default to no cross-command caching
    if contract_class_cache is None:
        contract_class_cache = {}

    at_block = int_hash_or_latest(command.at_block)

    timings = {}
    started_at = time.time()

    # When calling or estimating the fee on a pending block, rust side will
    # always execute it on a specific block (pending's parent block). If that
    # block is not found, we should default to the latest block IFF there are
    # pending updates or deploys or nonces.
    fallback_to_latest = isinstance(at_block, bytes) and command.has_pending_data()

    pending_updates = command.pending_updates
    pending_deployed = command.pending_deployed
    pending_nonces = command.pending_nonces

    # the later parts will have access to gas_price through this block_info
    try:
        (block_info, global_root) = resolve_block(
            connection, at_block, command.gas_price
        )
    except NoSuchBlock:
        if fallback_to_latest:
            pending_updates = {}
            pending_deployed = []
            pending_nonces = {}

            (block_info, global_root) = resolve_block(
                connection, "latest", command.gas_price
            )
        else:
            raise

    if command.get_pending_timestamp():
        block_info = dataclasses.replace(
            block_info, block_timestamp=command.get_pending_timestamp()
        )

    timings["resolve_block"] = time.time() - started_at
    started_at = time.time()

    general_config = create_general_config(command.chain.value)

    adapter = SqliteAdapter(connection)
    # hook up the sqlite adapter
    ffc = FactFetchingContext(storage=adapter, hash_func=pedersen_hash_func)
    state_reader = PatriciaStateReader(
        PatriciaTree(global_root, 251), ffc, contract_class_storage=adapter
    )
    async_state = CachedState(
        block_info=block_info,
        state_reader=state_reader,
        contract_class_cache=contract_class_cache,
    )

    apply_pending(async_state, pending_updates, pending_deployed, pending_nonces)

    if isinstance(command, Call):
        result = asyncio.run(
            do_call(
                async_state,
                general_config,
                command.contract_address,
                command.entry_point_selector,
                command.calldata,
            )
        )
        ret = (command.verb, result.retdata, timings)
    else:
        assert isinstance(command, EstimateFee)
        fees = asyncio.run(
            do_estimate_fee(
                async_state,
                general_config,
                block_info,
                command.transaction,
            )
        )
        ret = (command.verb, fees, timings)

    timings["sql"] = {
        "timings": adapter.elapsed,
        "counts": adapter.counts,
        "cache": adapter.cache,
    }
    timings["cairo-lang"] = time.time() - started_at

    return ret


def render(verb, vals):
    def prefixed_hex(x):
        return f"0x{x.to_bytes(32, 'big').hex()}"

    if verb == Verb.CALL:
        return list(map(prefixed_hex, vals))
    else:
        assert verb == Verb.ESTIMATE_FEE
        return {
            "gas_consumed": prefixed_hex(vals["gas_consumed"]),
            "gas_price": prefixed_hex(vals["gas_price"]),
            "overall_fee": prefixed_hex(vals["overall_fee"]),
        }


def int_hash_or_latest(s: str):
    if s == "latest":
        return s
    if s == "pending":
        # this is allowed in the rpc api but pathfinder doesn't create the blocks
        # this should had never come to us
        raise NoSuchBlock(s)

    if re.match("^0x[0-9a-f]+$", s) is not None:
        # block hash as bytes
        return int(s, 16).to_bytes(length=32, byteorder="big")
    if re.match("^[0-9]+$", s) is not None:
        # block number
        return int(s)

    raise ValueError(f"Invalid block id value: {s}")


def check_schema(connection):
    assert connection.in_transaction
    cursor = connection.execute("select user_version from pragma_user_version")
    assert cursor is not None, "there has to be an user_version defined in the database"

    [version] = next(cursor)
    return version == EXPECTED_SCHEMA_REVISION


def resolve_block(connection, at_block, forced_gas_price: int) -> BlockInfo:
    """
    forced_gas_price is the gas price we must use for this blockinfo, if None,
    the one from starknet_blocks will be used. this allows the caller to select
    where the gas_price information is coming from, and for example, select
    different one for latest pointed out by hash or tag.
    """

    if at_block == "latest":
        # it has been decided that the latest is whatever pathfinder knows to be latest synced block
        # regardless of it being the highest known (not yet synced)
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) order by number desc limit 1"
        )
    elif isinstance(at_block, int):
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) where number = ?",
            [at_block],
        )
    else:
        assert isinstance(at_block, bytes), f"expected bytes, got {type(at_block)}"
        if len(at_block) < 32:
            # left pad it, as the fields in db are fixed length for this occasion
            at_block = b"\x00" * (32 - len(at_block)) + at_block

        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) where hash = ?",
            [at_block],
        )

    try:
        [
            (
                block_number,
                block_time,
                global_root,
                gas_price,
                sequencer_address,
                starknet_version,
            )
        ] = cursor
    except ValueError as exc:
        # zero rows, or wrong number of columns (unlikely)
        raise NoSuchBlock(at_block) from exc

    gas_price = int.from_bytes(gas_price, "big")

    if forced_gas_price != 0:
        # allow caller to override any; see rust side's GasPriceSource for more rationale
        gas_price = forced_gas_price

    sequencer_address = int.from_bytes(sequencer_address, "big")

    return (
        BlockInfo(
            block_number, block_time, gas_price, sequencer_address, starknet_version
        ),
        global_root,
    )


class NoSuchBlock(Exception):
    def __init__(self, at_block):
        super().__init__(f"Could not find the block by: {at_block}")


class UnexpectedSchemaVersion(Exception):
    def __init__(self):
        super().__init__("Schema mismatch, is this pathfinders database file?")


class Logger:
    """
    Simple logging abstraction

    Over at rust side, there's a spawned task reading stderr line by line.
    On each line there should be <level><json> on a single line.
    """

    def error(self, message):
        self._log(0, message)

    def warn(self, message):
        self._log(1, message)

    def info(self, message):
        self._log(2, message)

    def debug(self, message):
        self._log(3, message)

    def trace(self, message):
        self._log(4, message)

    def _log(self, level, message):
        print(f"{level}{json.dumps(message)}", file=sys.stderr, flush=True)


class SqliteAdapter(Storage):
    """
    Reads from pathfinders' database to give cairo-lang call implementation the nodes as needed
    however using a single transaction.
    """

    def __init__(self, connection):
        assert connection.in_transaction, "first query should had started a transaction"
        self.connection = connection
        self.elapsed = {
            "total": 0,
            "patricia_node": 0,
            "contract_state": 0,
            "contract_definition": 0,
        }
        self.counts = {
            "total": 0,
            "patricia_node": 0,
            "contract_state": 0,
            "contract_definition": 0,
        }
        self.cache = {"patricia_node": {"hits": 0, "misses": 0}}
        # json cannot contain bytes, python doesn't have strip string
        self.prefix_mapping = {
            b"patricia_node": "patricia_node",
            b"contract_state": "contract_state",
            b"contract_definition_fact": "contract_definition",
            # this is just a string op
            b"starknet_storage_leaf": None,
        }
        self.cached_patricia_nodes = LRUCache(maxsize=512)

    async def set_value(self, key, value):
        raise NotImplementedError("Readonly storage, this should never happen")

    async def del_value(self, key):
        raise NotImplementedError("Readonly storage, this should never happen")

    async def get_value(self, key):
        started_at = time.time()

        # all keys have this structure
        [prefix, suffix] = key.split(b":", maxsplit=1)

        ret = self.get_value0(prefix, suffix)

        elapsed = time.time() - started_at

        self.elapsed["total"] += elapsed
        self.counts["total"] += 1
        # bytes are not permitted in json
        prefix = self.prefix_mapping.get(prefix, None)
        if prefix is not None:
            self.elapsed[prefix] += elapsed
            self.counts[prefix] += 1
        return ret

    def get_value0(self, prefix, suffix):
        """
        Get value invoked by some storage thing from cairo-lang. The caller
        will assert that the values returned are not None, which sometimes
        bubbles up, or gets wrapped in a StarkException.
        """

        # cases handled in the order of appereance
        if prefix == b"patricia_node":
            return self.fetch_patricia_node(suffix)

        if prefix == b"contract_state":
            return self.fetch_contract_state(suffix)

        if prefix == b"contract_definition_fact":
            return self.fetch_contract_definition(suffix)

        if prefix == b"starknet_storage_leaf":
            return self.fetch_storage_leaf(suffix)

        assert False, f"unknown prefix: {prefix}"

    def fetch_patricia_node(self, suffix):
        cached = self.cached_patricia_nodes.get(suffix, None)
        if cached is not None:
            self.cache["patricia_node"]["hits"] += 1
            return cached

        # tree_global is much smaller table than tree_contracts
        cursor = self.connection.execute(
            "select data from tree_global where hash = ?1 union select data from tree_contracts where hash = ?1",
            [suffix],
        )

        [only] = next(cursor, [None])

        self.cached_patricia_nodes[suffix] = only
        self.cache["patricia_node"]["misses"] += 1

        return only

    def fetch_contract_state(self, suffix):
        cursor = self.connection.execute(
            "select hash, root, nonce from contract_states where state_hash = ?",
            [suffix],
        )

        only = next(cursor, [None, None, None])

        [h, root, nonce] = only

        if h is None or root is None:
            # finding contract_states is a special quest.
            #
            # we must return this because None is not handled by caller. for
            # some reason there is opposition to stopping cairo-lang's search
            # when they don't find a key in the patricia tree, so it ends up
            # making what seems like full height queries and then reads
            # "contract_state:00..00" key, for which it hopes to find this to
            # know that the leaf and the contract state did not exist.
            return NOT_FOUND_CONTRACT_STATE

        return (
            b'{"storage_commitment_tree": {"root": "'
            + root.hex().encode("utf-8")
            + b'", "height": 251}, "contract_hash": "'
            + h.hex().encode("utf-8")
            + b'", "nonce": "0x'
            + nonce.hex().encode("utf-8")
            + b'"}'
        )

    def fetch_contract_definition(self, suffix):
        # assert False, "we must rebuild the full json out of our columns"
        cursor = self.connection.execute(
            "select definition from class_definitions where hash = ?", [suffix]
        )
        [only] = next(cursor, [None])

        if only is None:
            return None

        # pathfinder stores zstd compressed json blobs
        decompressor = zstandard.ZstdDecompressor()
        only = decompressor.decompress(only)

        # cairo-lang expects a ContractDefinitionFact, however we store just
        # the contract definition over at pathfinder (from full_contract)
        # so we need to wrap it up here. itertools is suggested by the manuals,
        # so lets hope it's the most efficient thing.
        #
        # there might be a better way to do this, since cairo-lang seems to
        # expect the returned value to have method called decode, but it's not
        # like we could fake streaming decompression
        return bytes(itertools.chain(b'{"contract_definition":', only, b"}"))

    def fetch_storage_leaf(self, suffix):
        # these are "stored" under their keys where key == value; this
        # follows from the inheritance structure inside cairo-lang
        return suffix


async def do_call(
    async_state: CachedState,
    general_config,
    contract_address,
    selector,
    calldata,
):
    """
    The actual call execution with cairo-lang.
    """

    resource_manager = ExecutionResourcesManager.empty()

    # I don't think this makes any sense for external calls
    caller_address = 0

    eep = ExecuteEntryPoint.create(
        contract_address, calldata, selector, caller_address, EntryPointType.EXTERNAL
    )

    # for testing runs it in the current asyncio event loop, just as we want it
    call_info = await eep.execute_for_testing(
        async_state, general_config, resource_manager
    )

    # return both of these as carried state is needed for the fee estimation afterwards
    return call_info


async def do_estimate_fee(
    async_state: CachedState,
    general_config: StarknetGeneralConfig,
    block_info: BlockInfo,
    transaction: AccountTransaction,
):
    """
    This is distinct from the call because estimating a fee requires flushing the state to count
    the amount of writes and other resource usage. Also, call doesn't require all of the information
    an estimate fee requires, but that is a bit in flux, as estimate_fee might need to work with
    deploy and perhaps declare transactions as well.
    """

    more = InternalAccountTransactionForSimulate.from_external(
        transaction, general_config
    )

    tx_info = await more.apply_state_updates(async_state, general_config)

    # with 0.10 upgrade we changed to division with gas_consumed as well, since
    # there is opposition to providing the non-multiplied scalar value from
    # cairo-lang.
    return {
        "gas_consumed": tx_info.actual_fee // max(1, block_info.gas_price),
        "gas_price": block_info.gas_price,
        "overall_fee": tx_info.actual_fee,
    }


def apply_pending(
    state: CachedState,
    updates: Dict[int, List[StorageDiff]],
    deployed: List[DeployedContract],
    nonces: Dict[int, int],
):
    for deployed_contract in deployed:
        state.cache._class_hash_initial_values[
            deployed_contract.address
        ] = deployed_contract.contract_hash.to_bytes(length=32, byteorder="big")

    for addr, updates in updates.items():
        for update in updates:
            state.cache._storage_initial_values[(addr, update.key)] = update.value

    for addr, nonce in nonces.items():
        # bypass the CachedState.increment_nonce which would give extra queries
        # per each, and only single step at a time
        state.cache._nonce_initial_values[addr] = nonce


def create_general_config(chain_id: StarknetChainId) -> StarknetGeneralConfig:
    """
    Separate fn because it's tricky to get a new instance with actual configuration
    """

    weights = resource_fee_weights_0_10_2

    # because of units ... scale these down
    weights = dict(map(lambda t: (t[0], t[1] * 0.05), weights.items()))

    general_config = StarknetGeneralConfig(
        starknet_os_config=StarknetOsConfig(chain_id),
        cairo_resource_fee_weights=weights,
    )

    assert general_config.cairo_resource_fee_weights[f"{N_STEPS_RESOURCE}"] == 0.05

    return general_config


# given on 2022-11-10
resource_fee_weights_0_10_2 = {
    N_STEPS_RESOURCE: 1.0,
    # these need to be suffixed because ... they are checked to have these suffixes, except for N_STEPS_RESOURCE
    f"{PEDERSEN_BUILTIN}_builtin": 32.0,
    f"{RANGE_CHECK_BUILTIN}_builtin": 16.0,
    f"{ECDSA_BUILTIN}_builtin": 2048.0,
    f"{BITWISE_BUILTIN}_builtin": 64.0,
    f"{OUTPUT_BUILTIN}_builtin": 0.0,
    f"{EC_OP_BUILTIN}_builtin": 1024.0,
}

if __name__ == "__main__":
    main()

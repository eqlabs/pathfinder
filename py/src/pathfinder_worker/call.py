import asyncio
import dataclasses
import json
import os
import re
import sqlite3
import sys
import time
import traceback
from abc import abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar, Dict, List, Optional, Tuple, Type

import pkg_resources

try:
    import starknet_pathfinder_crypto
    import starkware.cairo.common.poseidon_hash
    import starkware.crypto.signature.fast_pedersen_hash

    starkware.crypto.signature.fast_pedersen_hash.pedersen_hash_func = (
        starknet_pathfinder_crypto.pedersen_hash_func
    )
    starkware.crypto.signature.fast_pedersen_hash.pedersen_hash = (
        starknet_pathfinder_crypto.pedersen_hash
    )
    starkware.cairo.common.poseidon_hash.poseidon_hash = (
        starknet_pathfinder_crypto.poseidon_hash
    )
    starkware.cairo.common.poseidon_hash.poseidon_hash_func = (
        starknet_pathfinder_crypto.poseidon_hash_func
    )
    starkware.cairo.common.poseidon_hash.poseidon_hash_many = (
        starknet_pathfinder_crypto.poseidon_hash_many
    )
    starkware.cairo.common.poseidon_hash.poseidon_perm = (
        starknet_pathfinder_crypto.poseidon_perm
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
    from cachetools import LRUCache
    from marshmallow import Schema
    from marshmallow import fields as mfields
    from services.everest.definitions import fields as everest_fields
    from starkware.starknet.business_logic.execution.execute_entry_point import (
        ExecuteEntryPoint,
    )
    from starkware.starknet.business_logic.execution.objects import (
        ExecutionResourcesManager,
    )
    from starkware.starknet.business_logic.state.state import BlockInfo, CachedState
    from starkware.starknet.core.os.contract_class.utils import (
        ClassHashType,
        class_hash_cache_ctx_var,
        set_class_hash_cache,
    )
    from starkware.starknet.definitions import constants, fields
    from starkware.starknet.definitions.constants import GasCost
    from starkware.starknet.definitions.error_codes import StarknetErrorCode
    from starkware.starknet.definitions.general_config import (
        DEFAULT_GAS_PRICE,
        DEFAULT_MAX_STEPS,
        DEFAULT_SEQUENCER_ADDRESS,
        DEFAULT_VALIDATE_MAX_STEPS,
        StarknetChainId,
        StarknetGeneralConfig,
        build_general_config,
    )
    from starkware.starknet.public.abi import starknet_keccak
    from starkware.starknet.services.api.contract_class.contract_class import (
        EntryPointType,
    )
    from starkware.starknet.services.api.contract_class.contract_class_utils import (
        compile_contract_class,
    )
    from starkware.starknet.services.api.feeder_gateway.response_objects import (
        BaseResponseObject,
        FunctionInvocation,
        TransactionTrace,
    )
    from starkware.starknet.services.api.gateway.transaction import (
        AccountTransaction,
        Declare,
        DeprecatedDeclare,
    )
    from starkware.starknet.services.utils.sequencer_api_utils import (
        InternalAccountTransactionForSimulate,
    )
    from starkware.starkware_utils.error_handling import StarkException

    from .storage import SqliteStateReader

except ModuleNotFoundError:
    print(
        "missing cairo-lang module: please reinstall dependencies to upgrade.",
    )
    sys.exit(1)


# used from tests, and the query which asserts that the schema is of expected version.
EXPECTED_SCHEMA_REVISION = 33
EXPECTED_CAIRO_VERSION = "0.11.0.2"

# this is set by pathfinder automatically when #[cfg(debug_assertions)]
DEV_MODE = os.environ.get("PATHFINDER_PROFILE") == "dev"


class Verb(Enum):
    CALL = 0
    ESTIMATE_FEE = 1
    SIMULATE_TX = 2


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

optional_class_hash_metadata = dict(
    marshmallow_field=fields.OptionalClassHashIntField.get_marshmallow_field()
)

class_hash_list_metadata = dict(
    marshmallow_field=mfields.List(
        fields.OptionalClassHashIntField.get_marshmallow_field()
    )
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


@marshmallow_dataclass.dataclass(frozen=True)
class TransactionAndClassHashHint:
    transaction: AccountTransaction
    class_hash_hint: Optional[int] = field(metadata=optional_class_hash_metadata)


@dataclass(frozen=True)
class Command:
    at_block: str
    chain: Chain

    pending_updates: Dict[int, List[StorageDiff]] = field(
        metadata=pending_updates_metadata
    )
    pending_deployed: List[DeployedContract] = field(metadata=pending_deployed_metadata)
    pending_nonces: Dict[int, int] = field(metadata=pending_nonces_metadata)
    pending_timestamp: int = field(metadata=fields.timestamp_metadata)

    @property
    @classmethod
    @abstractmethod
    def verb(cls) -> Verb:
        """
        Returns the verb
        """

    def has_pending_data(self):
        return (
            len(self.pending_updates) > 0
            or len(self.pending_deployed) > 0
            or len(self.pending_nonces) > 0
        )

    def get_pending_timestamp(self) -> int:
        return self.pending_timestamp


@marshmallow_dataclass.dataclass(frozen=True)
class Call(Command):
    verb: ClassVar[Verb] = Verb.CALL

    contract_address: int = field(metadata=fields.contract_address_metadata)
    calldata: List[int] = field(metadata=fields.call_data_as_hex_metadata)
    entry_point_selector: Optional[int] = field(
        default=None, metadata=fields.optional_entry_point_selector_metadata
    )

    gas_price: int = 0


@marshmallow_dataclass.dataclass(frozen=True)
class EstimateFee(Command):
    verb: ClassVar[Verb] = Verb.ESTIMATE_FEE

    # zero means to use the gas price from the current block.
    gas_price: int = field(metadata=fields.gas_price_metadata)

    transactions: List[TransactionAndClassHashHint]


@marshmallow_dataclass.dataclass(frozen=True)
class SimulateTx(Command):
    verb: ClassVar[Verb] = Verb.SIMULATE_TX

    # zero means to use the gas price from the current block.
    gas_price: int = field(metadata=fields.gas_price_metadata)

    transactions: List[TransactionAndClassHashHint]
    skip_validate: bool


class CommandSchema(marshmallow_oneofschema.OneOfSchema):
    type_field = "verb"
    type_schemas: Dict[str, Type[Schema]] = {
        Verb.CALL.name: Call.Schema,
        Verb.ESTIMATE_FEE.name: EstimateFee.Schema,
        Verb.SIMULATE_TX.name: SimulateTx.Schema,
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


def do_loop(connection: sqlite3.Connection, input_gen, output_file):
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


def loop_inner(
    connection: sqlite3.Connection, command: Command, contract_class_cache=None
):
    logger = Logger()

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
        (block_info, storage_commitment, class_commitment) = resolve_block(
            connection, at_block, command.gas_price
        )
    except NoSuchBlock:
        if fallback_to_latest:
            pending_updates = {}
            pending_deployed = []
            pending_nonces = {}

            (block_info, storage_commitment, class_commitment) = resolve_block(
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

    state_reader = SqliteStateReader(connection, block_number=block_info.block_number)
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
    elif isinstance(command, EstimateFee):
        fees = asyncio.run(
            do_estimate_fee(
                async_state,
                general_config,
                block_info,
                command.transactions,
            )
        )
        ret = (command.verb, fees, timings)
    elif isinstance(command, SimulateTx):
        simulated_transactions = asyncio.run(
            do_simulate_tx(
                async_state,
                general_config,
                block_info,
                command.transactions,
                command.skip_validate,
            )
        )
        ret = (command.verb, simulated_transactions, timings)
    else:
        logger.error(f"Unrecognised command: {command}")

    timings["cairo-lang"] = time.time() - started_at

    return ret


def render(verb, vals):
    if verb == Verb.CALL:
        return list(map(as_hex, vals))
    elif verb == Verb.ESTIMATE_FEE:
        return FeeEstimation.Schema(many=True).dump(vals)
    elif verb == Verb.SIMULATE_TX:
        return TransactionSimulation.Schema(many=True).dump(vals)


def as_hex(x):
    hex = x.to_bytes(32, "big").hex()
    return f"0x0{hex.lstrip('0')}"


@marshmallow_dataclass.dataclass(frozen=True)
class FeeEstimation(BaseResponseObject):
    gas_consumed: int = field(metadata=felt_metadata)
    gas_price: int = field(metadata=felt_metadata)
    overall_fee: int = field(metadata=felt_metadata)


@marshmallow_dataclass.dataclass(frozen=True)
class TransactionSimulation(BaseResponseObject):
    trace: TransactionTrace
    fee_estimation: FeeEstimation


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


def resolve_block(
    connection: sqlite3.Connection, at_block, forced_gas_price: int
) -> Tuple[BlockInfo, int, int]:
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
            "select number, timestamp, root, gas_price, sequencer_address, class_commitment, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) order by number desc limit 1"
        )
    elif isinstance(at_block, int):
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, class_commitment, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) where number = ?",
            [at_block],
        )
    else:
        assert isinstance(at_block, bytes), f"expected bytes, got {type(at_block)}"
        if len(at_block) < 32:
            # left pad it, as the fields in db are fixed length for this occasion
            at_block = b"\x00" * (32 - len(at_block)) + at_block

        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, class_commitment, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) where hash = ?",
            [at_block],
        )

    try:
        [
            (
                block_number,
                block_time,
                storage_commitment,
                gas_price,
                sequencer_address,
                class_commitment,
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
        storage_commitment,
        class_commitment,
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
        contract_address,
        calldata,
        selector,
        caller_address,
        initial_gas=GasCost.INITIAL.value,
        entry_point_type=EntryPointType.EXTERNAL,
    )

    # for testing runs it in the current asyncio event loop, just as we want it
    call_info = await eep.execute_for_testing(
        async_state, general_config, resource_manager
    )

    # return both of these as carried state is needed for the fee estimation afterwards
    return call_info


async def simulate_account_tx(
    state: CachedState,
    general_config: StarknetGeneralConfig,
    transaction_and_class_hint: TransactionAndClassHashHint,
    skip_validate: bool,
):

    class_hash_hint = transaction_and_class_hint.class_hash_hint
    transaction = transaction_and_class_hint.transaction

    if class_hash_hint is not None:
        cache = class_hash_cache_ctx_var.get()

        if isinstance(transaction, Declare):
            contract_class_bytes = transaction.contract_class.dumps(
                sort_keys=True
            ).encode()
            key = (
                ClassHashType.CONTRACT_CLASS,
                starknet_keccak(data=contract_class_bytes),
            )
        elif isinstance(transaction, DeprecatedDeclare):
            contract_class_bytes = transaction.contract_class.dumps(
                sort_keys=True
            ).encode()
            key = (
                ClassHashType.DEPRECATED_COMPILED_CLASS,
                starknet_keccak(data=contract_class_bytes),
            )
        else:
            raise ValueError("Unexpected class hash hint for non-declare transaction")

        cache[key] = class_hash_hint

    internal_transaction = InternalAccountTransactionForSimulate.create_for_simulate(
        transaction, general_config, skip_validate
    )

    with state.copy_and_apply() as state_copy:
        tx_info = await internal_transaction.apply_state_updates(
            state_copy, general_config
        )

    # apply class declarations manually to state,
    # since apply_state_updates() does not do this
    if isinstance(transaction, Declare):
        compiled_class = compile_contract_class(
            transaction.contract_class,
            allowed_libfuncs_list_name="experimental_v0.1.0",
        )
        state.contract_classes[transaction.compiled_class_hash] = compiled_class
    elif isinstance(transaction, DeprecatedDeclare):
        state.contract_classes[
            internal_transaction.class_hash
        ] = transaction.contract_class

    return tx_info


async def do_estimate_fee(
    state: CachedState,
    general_config: StarknetGeneralConfig,
    block_info: BlockInfo,
    transactions: List[TransactionAndClassHashHint],
):
    """
    This is distinct from the call because estimating a fee requires flushing the state to count
    the amount of writes and other resource usage. Also, call doesn't require all of the information
    an estimate fee requires, but that is a bit in flux, as estimate_fee might need to work with
    deploy and perhaps declare transactions as well.
    """

    fees = []

    class_hash_cache = LRUCache(maxsize=128)

    with set_class_hash_cache(class_hash_cache):
        for transaction in transactions:
            tx_info = await simulate_account_tx(
                state, general_config, transaction, skip_validate=False
            )

            fee = FeeEstimation(
                gas_price=block_info.gas_price,
                gas_consumed=tx_info.actual_fee // max(1, block_info.gas_price),
                overall_fee=tx_info.actual_fee,
            )

            # with 0.10 upgrade we changed to division with gas_consumed as well, since
            # there is opposition to providing the non-multiplied scalar value from
            # cairo-lang.
            fees.append(fee)

    return fees


async def do_simulate_tx(
    state: CachedState,
    general_config: StarknetGeneralConfig,
    block_info: BlockInfo,
    transactions: List[TransactionAndClassHashHint],
    skip_validate: bool,
):
    simulated_transactions = []

    class_hash_cache = LRUCache(maxsize=128)
    with set_class_hash_cache(class_hash_cache):
        for transaction in transactions:
            tx_info = await simulate_account_tx(
                state, general_config, transaction, skip_validate
            )

            trace = TransactionTrace(
                validate_invocation=FunctionInvocation.from_optional_internal(
                    tx_info.validate_info
                ),
                function_invocation=FunctionInvocation.from_optional_internal(
                    tx_info.call_info
                ),
                fee_transfer_invocation=FunctionInvocation.from_optional_internal(
                    tx_info.fee_transfer_info
                ),
                signature=transaction.transaction.signature,
            )

            fee_estimation = FeeEstimation(
                gas_price=block_info.gas_price,
                gas_consumed=tx_info.actual_fee // max(1, block_info.gas_price),
                overall_fee=tx_info.actual_fee,
            )

            simulated_transactions.append(TransactionSimulation(trace, fee_estimation))

    return simulated_transactions


def apply_pending(
    state: CachedState,
    updates: Dict[int, List[StorageDiff]],
    deployed: List[DeployedContract],
    nonces: Dict[int, int],
):
    for deployed_contract in deployed:
        # pylint: disable=protected-access
        state.cache._class_hash_initial_values[
            deployed_contract.address
        ] = deployed_contract.contract_hash

    for addr, updates in updates.items():
        for update in updates:
            # pylint: disable=protected-access
            state.cache._storage_initial_values[(addr, update.key)] = update.value

    for addr, nonce in nonces.items():
        # bypass the CachedState.increment_nonce which would give extra queries
        # per each, and only single step at a time
        # pylint: disable=protected-access
        state.cache._nonce_initial_values[addr] = nonce


def create_general_config(chain_id: StarknetChainId) -> StarknetGeneralConfig:
    """
    Separate fn because it's tricky to get a new instance with actual configuration
    """
    # starknet's ETHER L2 token address.
    # Taken from: https://github.com/starknet-io/starknet-addresses/blob/df19b17d2c83f11c30e65e2373e8a0c65446f17c/bridged_tokens/goerli.json#L43
    ETHER_L2_TOKEN_ADDRESS = (
        "0x049d36570d4e46f48e99674bd3fcc84644ddd6b96f7c741b1562b82f9e004dc7"
    )

    return build_general_config(
        {
            "cairo_resource_fee_weights": {"n_steps": constants.N_STEPS_FEE_WEIGHT},
            "compiled_class_hash_commitment_tree_height": constants.COMPILED_CLASS_HASH_COMMITMENT_TREE_HEIGHT,
            "contract_storage_commitment_tree_height": constants.CONTRACT_STATES_COMMITMENT_TREE_HEIGHT,
            "enforce_l1_handler_fee": False,
            "event_commitment_tree_height": constants.EVENT_COMMITMENT_TREE_HEIGHT,
            "global_state_commitment_tree_height": constants.CONTRACT_ADDRESS_BITS,
            "invoke_tx_max_n_steps": DEFAULT_MAX_STEPS,
            "min_gas_price": DEFAULT_GAS_PRICE,
            "sequencer_address": hex(DEFAULT_SEQUENCER_ADDRESS),
            "starknet_os_config": {
                "chain_id": chain_id.value,
                "fee_token_address": ETHER_L2_TOKEN_ADDRESS,
            },
            "tx_version": constants.TRANSACTION_VERSION,
            "tx_commitment_tree_height": constants.TRANSACTION_COMMITMENT_TREE_HEIGHT,
            "validate_max_n_steps": DEFAULT_VALIDATE_MAX_STEPS,
        }
    )


if __name__ == "__main__":
    main()

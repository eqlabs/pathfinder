import sys
import json
import time
import sqlite3
import asyncio
import os

# FIXME: when pathfinder is launched with missing dependencies, this will be
# logged out, which is very unclear and confuses users. it would be better to
# go through with importlib or whatever fallible way to import
from starkware.storage.storage import Storage

# used from tests, and the query which asserts that the schema is of expected version.
EXPECTED_SCHEMA_REVISION = 20
EXPECTED_CAIRO_VERSION = "0.10.0"
SUPPORTED_COMMANDS = frozenset(["call", "estimate_fee"])

# used by the sqlite adapter to communicate "contract state not found, nor was the patricia tree key"
NOT_FOUND_CONTRACT_STATE = b'{"contract_hash": "0000000000000000000000000000000000000000000000000000000000000000", "nonce": "0x0", "storage_commitment_tree": {"height": 251, "root": "0000000000000000000000000000000000000000000000000000000000000000"}}'

# this is set by pathfinder automatically when #[cfg(debug_assertions)]
DEV_MODE = os.environ.get("PATHFINDER_PROFILE") == "dev"


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

    with sqlite3.connect(database_path) as connection:
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
    import pkg_resources

    version = pkg_resources.get_distribution("cairo-lang").version
    return version == EXPECTED_CAIRO_VERSION


def do_loop(connection, input_gen, output_file):
    from starkware.starkware_utils.error_handling import WebFriendlyException

    required = {
        "at_block": int_hash_or_latest,
        "contract_address": int_param,
        "entry_point_selector": string_or_int,
        "calldata": list_of_int,
        "command": required_command,
        "gas_price": required_gas_price,
        "chain": required_chain,
    }

    optional = {
        "signature": list_of_int,
        "max_fee": int_param,
        "version": int_param,
        "pending_updates": maybe_pending_updates,
        "pending_deployed": maybe_pending_deployed,
        "pending_nonces": maybe_pending_nonces,
        "nonce": maybe_nonce,
    }

    logger = Logger()

    if DEV_MODE:
        logger.warn(
            "dev mode enabled, expect long tracebacks; do not use in production!"
        )

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
            command = parse_command(json.loads(line), required, optional)

            parsed_at = time.time()

            connection.execute("BEGIN")

            [verb, output, inner_timings] = loop_inner(connection, command)

            # this is more backwards compatible dictionary union
            timings = {**timings, **inner_timings}

            out["output"] = render(verb, output)
        except NoSuchBlock:
            out = {"status": "error", "kind": "NO_SUCH_BLOCK"}
        except UnexpectedSchemaVersion:
            out = {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}
        except InvalidInput:
            out = {"status": "error", "kind": "INVALID_INPUT"}
        except WebFriendlyException as e:
            if str(e.code) == "StarknetErrorCode.UNINITIALIZED_CONTRACT":
                out = {"status": "error", "kind": "NO_SUCH_CONTRACT"}
            elif str(e.code) == "StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT":
                out = {"status": "error", "kind": "INVALID_ENTRY_POINT"}
            else:
                report_failed(logger, command, e)
                out = {"status": "failed", "exception": str(e.code)}
        except Exception as e:
            stringified = str(e)

            if len(stringified) > 200:
                stringified = stringified[:197] + "..."
            report_failed(logger, command, e)
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
        import traceback

        strs = traceback.format_exception(type(e), e, e.__traceback__)
        logger.debug("".join(strs))
    else:
        logger.debug(str(e))


def loop_inner(connection, command):

    if not check_schema(connection):
        raise UnexpectedSchemaVersion

    verb = command["command"]
    general_config = create_general_config(command["chain"])

    at_block = command["at_block"]
    # this will be None for v1 invoke function
    selector = command.get("entry_point_selector", None)
    signature = command.get("signature", [])
    max_fee = command.get("max_fee", 0)
    version = command.get("version", 0)
    gas_price = command.get("gas_price", None)

    timings = {}
    started_at = time.time()
    pending_updates = command.get("pending_updates", None)
    pending_deployed = command.get("pending_deployed", None)
    pending_nonces = command.get("pending_nonces", None)

    if type(selector) == str:
        from starkware.starknet.public.abi import get_selector_from_name

        # rust side will always send us starkhashes but tests are more readable with names
        selector = get_selector_from_name(selector)

    fallback_to_latest = type(at_block) == bytes and (
        pending_updates is not None or pending_deployed is not None
    )

    # the later parts will have access to gas_price through this block_info
    try:
        (block_info, global_root) = resolve_block(connection, at_block, gas_price)
    except NoSuchBlock:
        if fallback_to_latest:
            pending_updates = None
            pending_deployed = None

            (block_info, global_root) = resolve_block(connection, "latest", gas_price)
        else:
            raise

    timings["resolve_block"] = time.time() - started_at
    started_at = time.time()

    adapter = SqliteAdapter(connection)

    if verb == "call":
        result = asyncio.run(
            do_call(
                adapter,
                general_config,
                global_root,
                command["contract_address"],
                selector,
                command["calldata"],
                signature,
                command.get("nonce", None),
                max_fee,
                block_info,
                version,
                pending_updates,
                pending_deployed,
                pending_nonces,
            )
        )
        ret = (verb, result.retdata, timings)
    else:
        assert verb == "estimate_fee"
        # do everything with the inheritance scheme
        fees = asyncio.run(
            do_estimate_fee(
                adapter,
                general_config,
                global_root,
                command["contract_address"],
                selector,
                command["calldata"],
                signature,
                command.get("nonce", None),
                max_fee,
                block_info,
                version,
                pending_updates,
                pending_deployed,
                pending_nonces,
            )
        )
        ret = (verb, fees, timings)

    timings["sql"] = {"timings": adapter.elapsed, "counts": adapter.counts}
    timings["call"] = time.time() - started_at

    return ret


def render(verb, vals):
    def prefixed_hex(x):
        return f"0x{x.to_bytes(32, 'big').hex()}"

    if verb == "call":
        return list(map(prefixed_hex, vals))
    else:
        assert verb == "estimate_fee"
        return {
            "gas_consumed": prefixed_hex(vals["gas_consumed"]),
            "gas_price": prefixed_hex(vals["gas_price"]),
            "overall_fee": prefixed_hex(vals["overall_fee"]),
        }


def parse_command(command, required, optional):
    # it would be nice to use marshmallow but before we can lock with
    # cairo-lang we cannot really add common dependencies
    missing = required.keys() - command.keys()
    assert len(missing) == 0, f"missing keys from command: {missing}"

    extra = set()

    converted = dict()

    for k, v in command.items():
        conv = required.get(k, None)
        if conv is None:
            conv = optional.get(k, None)
        if conv is None:
            extra += k
            continue

        try:
            converted[k] = conv(v)
        except Exception:
            raise InvalidInput(k)

    assert len(extra) == 0, f"extra keys from command: {extra}"

    return converted


def int_hash_or_latest(s):
    if type(s) == int:
        return s
    if s == "latest":
        return s
    if s == "pending":
        # this is allowed in the rpc api but pathfinder doesn't create the blocks
        # this should had never come to us
        raise NoSuchBlock(s)
    assert s[0:2] == "0x"
    return len_safe_hex(s)


def int_param(s):
    if type(s) == int:
        return s
    if s.startswith("0x"):
        return int.from_bytes(len_safe_hex(s), "big")
    return int(s, 10)


def len_safe_hex(s):
    """
    Over at the RPC side which pathfinder supports, sometimes hex without
    leading zeros is needed, so they could come over to python as well.
    bytes.fromhex doesn't support odd length hex, it gives a non-hex character
    error.
    """
    if s.startswith("0x"):
        s = s[2:]
    if len(s) % 2 == 1:
        s = "0" + s
    return bytes.fromhex(s)


def string_or_int(s):
    if type(s) == int:
        return s

    if type(s) == str:
        if s.startswith("0x"):
            return int_param(s)
        # not sure if this should be supported but strings get ran through the
        # truncated keccak
        return s

    raise TypeError(f"expected string or int, not {type(s)}")


def list_of_int(s):
    assert type(s) == list, f"Expected list, got {type(s)}"
    return list(map(int_param, s))


def required_command(s):
    assert s in SUPPORTED_COMMANDS
    return s


def required_gas_price(s):
    if s is None:
        # this means, use the block gas price
        return None
    elif type(s) == str:
        return int.from_bytes(len_safe_hex(s), "big")
    else:
        assert type(s) == int, "expected gas_price to be an int"
        return s


def required_chain(s):
    from starkware.starknet.definitions.general_config import StarknetChainId

    # this is not done through genesis block but explicitly so that we can do
    # tests more freely

    if s == "MAINNET":
        return StarknetChainId.MAINNET
    else:
        assert s == "GOERLI"
        return StarknetChainId.TESTNET


def maybe_pending_updates(s):
    if s is None:
        return None

    # currently just accepting the format from sequencers get_state_update
    return dict(
        (
            int_param(key),
            list((int_param(val["key"]), int_param(val["value"])) for val in values),
        )
        for key, values in s.items()
    )


def maybe_pending_deployed(deployed_contracts):
    if deployed_contracts is None:
        return None

    # this accepts the form used in the sequencer state update
    # which is "prop": [ { "address": "0x...", "contract_hash": "0x..." }, ... ]
    # internally we use just address => hash

    return dict(
        (int_param(x["address"]), len_safe_hex(x["contract_hash"]))
        for x in deployed_contracts
    )


def maybe_pending_nonces(nonces):
    if nonces is None:
        return None

    # accept a map addr => nonce
    return dict((int_param(key), int_param(value)) for key, value in nonces.items())


def maybe_nonce(nonce):
    if nonce is None:
        return None

    return int_param(nonce)


def check_schema(connection):
    assert connection.in_transaction
    cursor = connection.execute("select user_version from pragma_user_version")
    assert cursor is not None, "there has to be an user_version defined in the database"

    [version] = next(cursor)
    return version == EXPECTED_SCHEMA_REVISION


def resolve_block(connection, at_block, forced_gas_price):
    """
    forced_gas_price is the gas price we must use for this blockinfo, if None,
    the one from starknet_blocks will be used. this allows the caller to select
    where the gas_price information is coming from, and for example, select
    different one for latest pointed out by hash or tag.
    """
    from starkware.starknet.business_logic.state.state import BlockInfo

    if at_block == "latest":
        # it has been decided that the latest is whatever pathfinder knows to be latest synced block
        # regardless of it being the highest known (not yet synced)
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) order by number desc limit 1"
        )
    elif type(at_block) == int:
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address, sn_ver.version from starknet_blocks left join starknet_versions sn_ver on (sn_ver.id = version_id) where number = ?",
            [at_block],
        )
    else:
        assert type(at_block) == bytes, f"expected bytes, got {type(at_block)}"
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
    except ValueError:
        # zero rows, or wrong number of columns (unlikely)
        raise NoSuchBlock(at_block)

    gas_price = int.from_bytes(gas_price, "big")

    if forced_gas_price is not None:
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


class InvalidInput(Exception):
    def __init__(self, key):
        super().__init__(f"Invalid input for key: {key}")


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
        # json cannot contain bytes, python doesn't have strip string
        self.prefix_mapping = {
            b"patricia_node": "patricia_node",
            b"contract_state": "contract_state",
            b"contract_definition_fact": "contract_definition",
            # this is just a string op
            b"starknet_storage_leaf": None,
        }

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
        # tree_global is much smaller table than tree_contracts
        cursor = self.connection.execute(
            "select data from tree_global where hash = ?1 union select data from tree_contracts where hash = ?1",
            [suffix],
        )

        [only] = next(cursor, [None])

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
        import itertools
        import zstandard

        # assert False, "we must rebuild the full json out of our columns"
        cursor = self.connection.execute(
            "select definition from contract_code where hash = ?", [suffix]
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
    adapter,
    general_config,
    root,
    contract_address,
    selector,
    calldata,
    signature,
    nonce,
    max_fee,
    block_info,
    version,
    pending_updates,
    pending_deployed,
    pending_nonces,
):
    """
    The actual call execution with cairo-lang.
    """
    from starkware.storage.storage import FactFetchingContext
    from starkware.starknet.business_logic.fact_state.patricia_state import (
        PatriciaStateReader,
    )
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starknet.business_logic.state.state import CachedState
    from starkware.starknet.business_logic.fact_state.state import (
        ExecutionResourcesManager,
    )
    from starkware.starknet.business_logic.execution.execute_entry_point import (
        ExecuteEntryPoint,
    )

    from starkware.starknet.services.api.contract_class import EntryPointType
    from starkware.cairo.lang.vm.crypto import pedersen_hash_func

    # hook up the sqlite adapter
    ffc = FactFetchingContext(storage=adapter, hash_func=pedersen_hash_func)
    state_reader = PatriciaStateReader(PatriciaTree(root, 251), ffc)
    async_state = CachedState(block_info, state_reader)

    apply_pending(async_state, pending_updates, pending_deployed, pending_nonces)

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
    adapter,
    general_config,
    root,
    contract_address,
    selector,
    calldata,
    signature,
    nonce,
    max_fee,
    block_info,
    version,
    pending_updates,
    pending_deployed,
    pending_nonces,
):
    """
    This is distinct from the call because estimating a fee requires flushing the state to count
    the amount of writes and other resource usage. Also, call doesn't require all of the information
    an estimate fee requires, but that is a bit in flux, as estimate_fee might need to work with
    deploy and perhaps declare transactions as well.
    """

    from starkware.starknet.services.api.gateway.transaction import InvokeFunction
    from starkware.starknet.services.utils.sequencer_api_utils import (
        InternalAccountTransactionForSimulate,
    )
    from starkware.storage.storage import FactFetchingContext
    from starkware.starknet.business_logic.fact_state.patricia_state import (
        PatriciaStateReader,
    )
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starknet.business_logic.state.state import CachedState
    from starkware.cairo.lang.vm.crypto import pedersen_hash_func

    fun = InvokeFunction(
        version=version,
        max_fee=max_fee,
        signature=signature,
        nonce=nonce,
        contract_address=contract_address,
        calldata=calldata,
        entry_point_selector=selector,
    )

    more = InternalAccountTransactionForSimulate.from_external(fun, general_config)

    ffc = FactFetchingContext(storage=adapter, hash_func=pedersen_hash_func)
    state_reader = PatriciaStateReader(PatriciaTree(root, 251), ffc)
    async_state = CachedState(block_info, state_reader)

    apply_pending(async_state, pending_updates, pending_deployed, pending_nonces)

    tx_info = await more.apply_state_updates(async_state, general_config)

    # with 0.10 upgrade we changed to division with gas_consumed as well, since
    # there is opposition to providing the non-multiplied scalar value from
    # cairo-lang.
    return {
        "gas_consumed": tx_info.actual_fee // max(1, block_info.gas_price),
        "gas_price": block_info.gas_price,
        "overall_fee": tx_info.actual_fee,
    }


def apply_pending(state, updates, deployed, nonces):
    updates = updates if updates is not None else {}
    deployed = deployed if deployed is not None else {}
    nonces = nonces if nonces is not None else {}

    for addr, class_hash in deployed.items():
        assert type(class_hash) == bytes
        state.cache._class_hash_reads[addr] = class_hash

    for addr, updates in updates.items():
        assert type(addr) == int
        for key, value in updates:
            assert type(key) == int
            assert type(value) == int
            state.cache._storage_reads[(addr, key)] = value

    for addr, nonce in nonces.items():
        assert type(addr) == int
        assert type(nonce) == int
        # bypass the CachedState.increment_nonce which would give extra queries
        # per each, and only single step at a time
        state.cache._nonce_reads[addr] = nonce


def create_general_config(chain_id):
    """
    Separate fn because it's tricky to get a new instance with actual configuration
    """
    from starkware.starknet.definitions.general_config import (
        StarknetGeneralConfig,
        N_STEPS_RESOURCE,
        StarknetOsConfig,
    )
    from starkware.cairo.lang.builtins.all_builtins import (
        PEDERSEN_BUILTIN,
        RANGE_CHECK_BUILTIN,
        ECDSA_BUILTIN,
        BITWISE_BUILTIN,
        OUTPUT_BUILTIN,
        EC_OP_BUILTIN,
    )

    # given on 2022-06-07
    weights = {
        N_STEPS_RESOURCE: 1.0,
        # these need to be suffixed because ... they are checked to have these suffixes, except for N_STEPS_RESOURCE
        f"{PEDERSEN_BUILTIN}_builtin": 8.0,
        f"{RANGE_CHECK_BUILTIN}_builtin": 8.0,
        f"{ECDSA_BUILTIN}_builtin": 512.0,
        f"{BITWISE_BUILTIN}_builtin": 256.0,
        f"{OUTPUT_BUILTIN}_builtin": 0.0,
        f"{EC_OP_BUILTIN}_builtin": 0.0,
    }

    # because of units ... scale these down
    weights = dict(map(lambda t: (t[0], t[1] * 0.05), weights.items()))

    general_config = StarknetGeneralConfig(
        starknet_os_config=StarknetOsConfig(chain_id),
        cairo_resource_fee_weights=weights,
    )

    assert general_config.cairo_resource_fee_weights[f"{N_STEPS_RESOURCE}"] == 0.05
    assert (
        general_config.cairo_resource_fee_weights[f"{BITWISE_BUILTIN}_builtin"] == 12.8
    )

    return general_config


if __name__ == "__main__":
    main()

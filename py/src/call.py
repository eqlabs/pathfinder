import sys
import json
import time
import sqlite3
import asyncio
from starkware.starkware_utils.error_handling import WebFriendlyException
from starkware.storage.storage import Storage

# used from tests, and the query which asserts that the schema is of expected version.
EXPECTED_SCHEMA_REVISION = 17
EXPECTED_CAIRO_VERSION = "0.9.1"
SUPPORTED_COMMANDS = frozenset(["call", "estimate_fee"])


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
    }

    logger = Logger()

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
        except NoSuchContract:
            out = {"status": "error", "kind": "NO_SUCH_CONTRACT"}
        except UnexpectedSchemaVersion:
            out = {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}
        except InvalidInput:
            out = {"status": "error", "kind": "INVALID_INPUT"}
        except WebFriendlyException as e:
            if str(e.code) == "StarknetErrorCode.ENTRY_POINT_NOT_FOUND_IN_CONTRACT":
                out = {"status": "error", "kind": "INVALID_ENTRY_POINT"}
            else:
                # as of cairo-lang 0.9.1 we don't have access to all exceptions
                # except as strings one with the longest stack traces is doing the
                # merkle tree reads to depth until a NoSuchContract
                stringified = str(e)
                if "\\ncall.NoSuchContract: Could not find the contract" in stringified:
                    # this is not turned into "status": "error", "kind": "NO_SUCH_CONTRACT" because
                    # it's unclear if that error code is wanted for nested calls failing with this
                    report_failed(
                        logger,
                        command,
                        f"Filtered nested NoSuchContract, original report was {len(stringified)} bytes",
                    )
                else:
                    report_failed(logger, command, e)
                # this is hopefully something we can give to the user
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
    logger.debug(str(e))


def loop_inner(connection, command):
    if not check_schema(connection):
        raise UnexpectedSchemaVersion

    verb = command["command"]
    general_config = create_general_config(command["chain"])

    at_block = command["at_block"]
    signature = command.get("signature", None)
    max_fee = command.get("max_fee", 0)
    version = command.get("version", 0)
    gas_price = command.get("gas_price", None)

    timings = {}
    started_at = time.time()
    pending_updates = command.get("pending_updates", None)
    pending_deployed = command.get("pending_deployed", None)

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

    (result, carried_state) = asyncio.run(
        do_call(
            adapter,
            general_config,
            global_root,
            command["contract_address"],
            command["entry_point_selector"],
            command["calldata"],
            signature,
            max_fee,
            block_info,
            version,
            pending_updates,
            pending_deployed,
        )
    )

    timings["sql"] = {"timings": adapter.elapsed, "counts": adapter.counts}

    timings["call"] = time.time() - started_at

    if verb == "call":
        return (verb, result.retdata, timings)
    else:
        assert verb == "estimate_fee", "command should had been call or estimate_fee"
        fees = estimate_fee_after_call(general_config, result, carried_state)
        return (verb, fees, timings)


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

    if s == "MAINNET":
        return StarknetChainId.MAINNET
    else:
        assert s == "GOERLI"
        return StarknetChainId.TESTNET


def maybe_pending_updates(s):
    if s is None:
        return None

    # currently just using the format from sequencers get_state_update
    return dict(
        map(
            lambda x: (
                # contract address needs to be an int
                int_param(x[0]),
                # many changes
                list(
                    map(
                        lambda y: {
                            "key": int_param(y["key"]),
                            "value": int_param(y["value"]),
                        },
                        x[1],
                    )
                ),
            ),
            s.items(),
        )
    )


def maybe_pending_deployed(deployed_contracts):
    if deployed_contracts is None:
        return None

    # this accepts the form used in the sequencer state update
    # which is "prop": [ { "address": "0x...", "contract_hash": "0x..." }, ... ]
    # internally we use just address => hash

    return dict(
        map(
            lambda x: (
                int_param(x["address"]),
                len_safe_hex(x["contract_hash"]),
            ),
            deployed_contracts,
        )
    )


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


class NoSuchContract(Exception):
    def __init__(self):
        """
        Nothing for this class can change without making other changes, since there's a string dependency.
        Look for `call.NoSuchContract: Could not find the contract`.
        """
        super().__init__("Could not find the contract")


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
            "select hash, root from contract_states where state_hash = ?", [suffix]
        )

        only = next(cursor, [None, None])

        [h, root] = only

        if h is None or root is None:
            if suffix == b"\x00" * 32:
                # this means that they went looking for a leaf in the patricia tree
                # but couldn't find anything which is signalled by many zeros key
                raise NoSuchContract
            return None

        return (
            b'{"storage_commitment_tree": {"root": "'
            + root.hex().encode("utf-8")
            + b'", "height": 251}, "contract_hash": "'
            + h.hex().encode("utf-8")
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
    max_fee,
    block_info,
    version,
    pending_updates,
    pending_deployed,
):
    """
    The actual call execution with cairo-lang.
    """
    from starkware.starknet.business_logic.state.state import (
        SharedState,
        StateSelector,
    )
    from starkware.storage.storage import FactFetchingContext
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.starkware_utils.commitment_tree.patricia_tree.nodes import (
        EmptyNodeFact,
    )
    from starkware.starknet.services.api.contract_class import EntryPointType
    from starkware.cairo.lang.vm.crypto import pedersen_hash_func
    from starkware.starknet.testing.state import create_invoke_function
    from starkware.starknet.storage.starknet_storage import StorageLeaf
    from starkware.starknet.business_logic.state.objects import (
        ContractState,
        ContractCarriedState,
    )

    # hook up the sqlite adapter
    ffc = FactFetchingContext(storage=adapter, hash_func=pedersen_hash_func)

    # the root tree has to always be height=251
    shared_state = SharedState(PatriciaTree(root, 251), block_info)

    # these needed to be moved to here because `test_call_on_reorgged_pending_block` provided
    # semantics on Nones at the command level
    pending_updates = pending_updates if pending_updates is not None else {}
    pending_deployed = pending_deployed if pending_deployed is not None else {}

    # we firstly want to load the target contract
    contract_addresses = {contract_address}
    # union all those contracts which have pending updates for
    contract_addresses = contract_addresses | pending_updates.keys()
    # exclude pending deploys, which should cause an issue reading them
    contract_addresses = contract_addresses ^ pending_deployed.keys()

    class_hashes = set()

    # include called contract's class hash to be loaded, it doesn't seem to be always
    # automatically loaded, see test `test_call_on_pending_deployed`.
    if contract_address in pending_deployed:
        class_hashes.add(pending_deployed[contract_address])

    # FIXME: it's unknown if this is really required, but we might end up loading up a lot of classes for nothing
    for class_hash in pending_deployed.values():
        class_hashes.add(class_hash)

    state_selector = StateSelector(contract_addresses, class_hashes)

    carried_state = await shared_state.get_filled_carried_state(ffc, state_selector)

    for addr, contract_hash in pending_deployed.items():
        # using ContractState.empty will write zero to database, which we fail as intended
        # this is essentially how to create an empty ContractState
        # this shouldn't be an async method
        cs = await ContractState.create(
            contract_hash, PatriciaTree(EmptyNodeFact.EMPTY_NODE_HASH, 251)
        )
        ccs = ContractCarriedState.from_state(cs)
        assert addr not in carried_state.contract_states
        carried_state.contract_states[addr] = ccs

    for addr, changes in pending_updates.items():
        ccs = carried_state.contract_states[addr]
        for change in changes:
            ccs.storage_updates[change["key"]] = StorageLeaf(change["value"])

    # using carried state as child_state is only required for fee estimation
    # but doesn't seem to matter for regular call.
    carried_state = carried_state.create_child_state_for_querying()

    # what follows is an inlined state.call_raw
    # FIXME: this needs to be restored in cairo-lang > 0.9.0 if there's an
    # option to access the carried state
    tx = create_invoke_function(
        contract_address=contract_address,
        selector=selector,
        calldata=calldata,
        caller_address=0,
        max_fee=max_fee,
        version=version,
        signature=signature,
        entry_point_type=EntryPointType.EXTERNAL,
        nonce=None,
        chain_id=general_config.chain_id.value,
        only_query=True,
    )

    call_info = await tx.execute(
        state=carried_state,
        general_config=general_config,
        only_query=True,
    )

    # return both of these as carried state is needed for the fee estimation afterwards
    return (call_info, carried_state)


def estimate_fee_after_call(general_config, call_info, carried_state):
    import math
    from starkware.starknet.business_logic.utils import get_invoke_tx_total_resources

    # FIXME: this is now completly inlined calculate_tx_fee, fix with cairo-lang 0.9.1
    # it has been adapted to variable names from 167b28bcd940fd25ea3816204fa882a0b0a49603
    (l1_gas_usage, cairo_resource_usage) = get_invoke_tx_total_resources(
        carried_state, call_info
    )

    cairo_resource_fee_weights = general_config.cairo_resource_fee_weights
    cairo_resource_names = set(cairo_resource_usage.keys())
    assert cairo_resource_names.issubset(
        cairo_resource_fee_weights.keys()
    ), "Cairo resource names must be contained in fee weights dict."

    # Convert Cairo usage to L1 gas usage.
    cairo_l1_gas_usage = max(
        cairo_resource_fee_weights[key] * cairo_resource_usage.get(key, 0)
        for key in cairo_resource_fee_weights
    )

    total_l1_gas_usage = cairo_l1_gas_usage + l1_gas_usage
    overall_fee = math.ceil(total_l1_gas_usage * carried_state.block_info.gas_price)

    return {
        "gas_consumed": int(total_l1_gas_usage),
        "gas_price": carried_state.block_info.gas_price,
        "overall_fee": int(overall_fee),
    }


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

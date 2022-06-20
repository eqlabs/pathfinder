import sys
import json
import time
import sqlite3
import asyncio
from starkware.starkware_utils.error_handling import WebFriendlyException
from starkware.storage.storage import Storage

# used from tests, and the query which asserts that the schema is of expected version.
EXPECTED_SCHEMA_REVISION = 12
EXPECTED_CAIRO_VERSION = "0.9.0"
SUPPORTED_COMMANDS = set(["call", "estimate_fee"])


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
    }

    optional = {
        "caller_address": int_param,
        "signature": int_param,
    }

    for line in input_gen:
        if line == "" or line.startswith("#"):
            continue

        out = {"status": "ok"}

        started_at = time.time()
        parsed_at = None

        try:
            command = parse_command(json.loads(line), required, optional)

            parsed_at = time.time()

            connection.execute("BEGIN")

            output = loop_inner(connection, command)

            out["output"] = render(*output)
        except NoSuchBlock:
            out = {"status": "error", "kind": "NO_SUCH_BLOCK"}
        except NoSuchContract:
            out = {"status": "error", "kind": "NO_SUCH_CONTRACT"}
        except UnexpectedSchemaVersion:
            out = {"status": "error", "kind": "INVALID_SCHEMA_VERSION"}
        except InvalidInput:
            out = {"status": "error", "kind": "INVALID_INPUT"}
        except WebFriendlyException as e:
            # this is hopefully something we can give to the user
            out = {"status": "failed", "exception": str(e.code)}
        except Exception as e:
            stringified = str(e)
            if len(stringified) > 200:
                stringified = stringified[:197] + "..."
            out = {"status": "failed", "exception": stringified}
        finally:
            connection.rollback()

            completed_at = time.time()
            timings = {}

            if parsed_at is not None and started_at < parsed_at:
                timings["parsing"] = parsed_at - started_at

            if parsed_at is not None and parsed_at < completed_at:
                timings["execution"] = completed_at - parsed_at

            out["timings"] = timings

            print(json.dumps(out), file=output_file, flush=True)


def loop_inner(connection, command):
    if not check_schema(connection):
        raise UnexpectedSchemaVersion

    verb = command["command"]

    # the later parts will have access to gas_price through this block_info
    (block_info, global_root) = resolve_block(
        connection, command["at_block"], command.get("gas_price", None)
    )

    (result, carried_state) = asyncio.run(
        do_call(
            SqliteAdapter(connection),
            global_root,
            command["contract_address"],
            command["entry_point_selector"],
            command["calldata"],
            command.get("caller_address", 0),
            command.get("signature", None),
            block_info,
        )
    )

    if verb == "call":
        return (verb, result.call_info.retdata)
    else:
        assert verb == "estimate_fee", "command should had been call or estimate_fee"
        fees = estimate_fee_after_call(result.call_info, carried_state)
        return (verb, fees)


def render(verb, vals):
    def prefixed_hex(x):
        return f"0x{x.to_bytes(32, 'big').hex()}"

    if verb == "call":
        # FIXME: if you set this to throw, for example forgetting result.call_info.retdata
        # on the RHS nested element, tests will still pass.
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


def check_schema(connection):
    global first
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
            "select number, timestamp, root, gas_price, sequencer_address from starknet_blocks order by number desc limit 1"
        )
    elif type(at_block) == int:
        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address from starknet_blocks where number = ?",
            [at_block],
        )
    else:
        assert type(at_block) == bytes, f"expected bytes, got {type(at_block)}"
        if len(at_block) < 32:
            # left pad it, as the fields in db are fixed length for this occasion
            at_block = b"\x00" * (32 - len(at_block)) + at_block

        cursor = connection.execute(
            "select number, timestamp, root, gas_price, sequencer_address from starknet_blocks where hash = ?",
            [at_block],
        )

    try:
        [(block_number, block_time, global_root, gas_price, sequencer_address)] = cursor
    except ValueError:
        # zero rows, or wrong number of columns (unlikely)
        raise NoSuchBlock(at_block)

    gas_price = int.from_bytes(gas_price, "big")

    if forced_gas_price is not None:
        # allow caller to override any; see rust side's GasPriceSource for more rationale
        gas_price = forced_gas_price

    sequencer_address = int.from_bytes(sequencer_address, "big")

    return (
        BlockInfo(block_number, block_time, gas_price, sequencer_address),
        global_root,
    )


class NoSuchBlock(Exception):
    def __init__(self, at_block):
        super().__init__(f"Could not find the block by: {at_block}")


class NoSuchContract(Exception):
    def __init__(self):
        super().__init__("Could not find the contract")


class UnexpectedSchemaVersion(Exception):
    def __init__(self):
        super().__init__("Schema mismatch, is this pathfinders database file?")


class InvalidInput(Exception):
    def __init__(self, key):
        super().__init__(f"Invalid input for key: {key}")


class SqliteAdapter(Storage):
    """
    Reads from pathfinders' database to give cairo-lang call implementation the nodes as needed
    however using a single transaction.
    """

    def __init__(self, connection):
        assert connection.in_transaction, "first query should had started a transaction"
        self.connection = connection

    async def set_value(self, key, value):
        raise NotImplementedError("Readonly storage, this should never happen")

    async def del_value(self, key):
        raise NotImplementedError("Readonly storage, this should never happen")

    async def get_value(self, key):
        """
        Get value invoked by some storage thing from cairo-lang. The caller
        will assert that the values returned are not None, which sometimes
        bubbles up, or gets wrapped in a StarkException.
        """
        # all keys have this structure
        [prefix, suffix] = key.split(b":", maxsplit=1)

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
            "select data from tree_global where hash = ?", [suffix]
        )

        [only] = next(cursor, [None])

        if only is None:
            # maybe UNION could be used here?
            cursor = self.connection.execute(
                "select data from tree_contracts where hash = ?", [suffix]
            )
            [only] = next(cursor, [None])

        return only

    def fetch_contract_state(self, suffix):
        cursor = self.connection.execute(
            "select hash, root from contract_states where state_hash = ?", [suffix]
        )

        # FIXME: this is really wonky, esp with the tuple returning query, the
        # first if is None is probably never hit.

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
    root,
    contract_address,
    selector,
    calldata,
    caller_address,
    signature,
    block_info,
):
    """
    Loads all of the cairo-lang parts needed for the call. Dirties the internal
    cairo-lang state which does not matter, because the state will be thrown
    out.

    Returns the retdata from the call, which is the only property needed by the RPC api.
    """
    from starkware.starknet.business_logic.state.state import (
        SharedState,
        StateSelector,
    )
    from starkware.starknet.definitions.general_config import StarknetGeneralConfig
    from starkware.storage.storage import FactFetchingContext
    from starkware.starkware_utils.commitment_tree.patricia_tree.patricia_tree import (
        PatriciaTree,
    )
    from starkware.cairo.lang.vm.crypto import pedersen_hash_func
    from starkware.starknet.testing.state import StarknetState

    general_config = StarknetGeneralConfig()

    # hook up the sqlite adapter
    ffc = FactFetchingContext(storage=adapter, hash_func=pedersen_hash_func)

    # the root tree has to always be height=251
    shared_state = SharedState(PatriciaTree(root=root, height=251), block_info)
    state_selector = StateSelector(
        contract_addresses={contract_address}, class_hashes=set()
    )
    carried_state = await shared_state.get_filled_carried_state(
        ffc, state_selector=state_selector
    )

    # using carried state as child_state is only required for fee estimation
    # but doesn't seem to matter for regular call.
    carried_state = carried_state.create_child_state_for_querying()

    state = StarknetState(state=carried_state, general_config=general_config)
    max_fee = 0

    output = await state.invoke_raw(
        contract_address, selector, calldata, caller_address, max_fee, signature
    )

    # return both of these as carried state is needed for the fee estimation afterwards
    return (output, carried_state)


def estimate_fee_after_call(call_info, carried_state):
    from starkware.starknet.definitions.general_config import (
        StarknetGeneralConfig,
        N_STEPS_RESOURCE,
    )
    from starkware.cairo.lang.builtins.all_builtins import (
        PEDERSEN_BUILTIN,
        RANGE_CHECK_BUILTIN,
        ECDSA_BUILTIN,
        BITWISE_BUILTIN,
        OUTPUT_BUILTIN,
        EC_OP_BUILTIN,
    )
    from starkware.starknet.business_logic.transaction_fee import calculate_tx_fee
    from starkware.starknet.business_logic.utils import get_invoke_tx_total_resources

    general_config = StarknetGeneralConfig()

    # given on 2022-06-07
    general_config.cairo_resource_fee_weights.update(
        {
            N_STEPS_RESOURCE: 1.0,
            PEDERSEN_BUILTIN: 8.0,
            RANGE_CHECK_BUILTIN: 8.0,
            ECDSA_BUILTIN: 512.0,
            BITWISE_BUILTIN: 256.0,
            OUTPUT_BUILTIN: 0.0,
            EC_OP_BUILTIN: 0.0,
        }
    )

    (l1_gas_used, _cairo_resources_used) = get_invoke_tx_total_resources(
        carried_state, call_info
    )

    overall_fee = calculate_tx_fee(carried_state, call_info, general_config)

    return {
        "gas_consumed": l1_gas_used,
        "gas_price": carried_state.block_info.gas_price,
        "overall_fee": overall_fee,
    }


if __name__ == "__main__":
    main()

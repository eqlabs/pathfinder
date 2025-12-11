import argparse
import json
import web3
from web3.exceptions import InvalidAddress
from typing import Dict, List
import os
import logging
from typing import Dict, List
from eth_typing.encoding import HexStr
from web3 import Web3
from web3.contract import Contract
logger = logging.getLogger(__name__)


def _initialize_memory_page_map(
    memory_page_fact_registry_contract: Contract, from_block: int, to_block: int
) -> Dict[int, str]:
    """
    Returns a mapping between the memory pages' hashes and the Ethereum transaction's hash for the
    transactions in blocks [from_block, to_block).
    """
    memory_page_contract_event = (
        memory_page_fact_registry_contract.events.LogMemoryPageFactContinuous
    )
    logger.info(
        f"Constructing memory pages dictionary for blocks [{from_block}, {to_block}].")
    memory_page_events = get_contract_events(
        contract_event=memory_page_contract_event, from_block=from_block, to_block=to_block
    )
    return {
        event["args"]["memoryHash"]: event["transactionHash"].hex() for event in memory_page_events
    }


def _initialize_fact_memory_hashes_map(
    statement_verifier_impl_contracts: List[Contract], from_block: int, to_block: int
) -> Dict[bytes, bytes]:
    """
    Given a list of statement verifier implementation contracts and block numbers, returns a mapping
    between Cairo job's fact and the memory pages hashes for each verifier contract.
    """
    statement_verifier_events = []
    for statement_verifier_impl_contract in statement_verifier_impl_contracts:
        # Asserts that the contract is a statement verifier implementation contract.
        assert (
            "GpsStatementVerifier" in statement_verifier_impl_contract.functions.identify().call()
        ), (
            f"Contract with address {statement_verifier_impl_contract.address} is not a "
            "statement verifier contract."
        )
        statement_verifier_contract_event = (
            statement_verifier_impl_contract.events.LogMemoryPagesHashes
        )
        statement_verifier_events.extend(
            get_contract_events(
                contract_event=statement_verifier_contract_event,
                from_block=from_block,
                to_block=to_block,
            )
        )
    return {
        event["args"]["factHash"]: event["args"]["pagesHashes"]
        for event in statement_verifier_events
    }


class MemoryPagesFetcher:
    """
    Given a fact hash and using onchain data, retrieves the memory pages that the GPS statement
    verifier outputted for the relevant Cairo job.
    """

    def __init__(
        self,
        web3: Web3,
        memory_page_transactions_map: Dict[int, str],
        fact_memory_pages_map: Dict[bytes, bytes],
        memory_page_fact_registry_contract: Contract,
    ):
        self.web3 = web3
        # Mapping from memory page hash to memory page Ethereum transaction.
        self.memory_page_transactions_map = memory_page_transactions_map
        # Mapping from Cairo job's fact to the Cairo job memory pages list.
        self.fact_memory_pages_map = fact_memory_pages_map
        self.memory_page_fact_registry_contract = memory_page_fact_registry_contract

    @classmethod
    def create(
        cls,
        web3: Web3,
        from_block: int,
        gps_statement_verifier_contract: Contract,
        memory_page_fact_registry_contract: Contract
    ) -> "MemoryPagesFetcher":
        """
        Creates an initialized instance by reading contract logs from the given web3 provider.
        If is_verifier_proxied is true, then gps_statement_verifier_contract is the proxy contract
        rather than the statement verifier implementation.
        """
        #last_block = web3.eth.block_number
        last_block = from_block + 10000
        memory_page_transactions_map = _initialize_memory_page_map(
            memory_page_fact_registry_contract=memory_page_fact_registry_contract,
            from_block=from_block,
            to_block=last_block,
        )
        gps_statement_verifier_impl_contracts = [
            gps_statement_verifier_contract]
        fact_memory_pages_map = _initialize_fact_memory_hashes_map(
            statement_verifier_impl_contracts=gps_statement_verifier_impl_contracts,
            from_block=from_block,
            to_block=last_block,
        )
        return cls(
            web3=web3,
            memory_page_transactions_map=memory_page_transactions_map,
            fact_memory_pages_map=fact_memory_pages_map,
            memory_page_fact_registry_contract=memory_page_fact_registry_contract,
        )

    def _get_memory_pages_hashes_from_fact(self, fact_hash: bytes):
        """
        An auxiliary function for retrieving the memory pages' hashes of a fact.
        """
        if fact_hash not in self.fact_memory_pages_map:
            raise Exception(
                f"Fact hash {fact_hash.hex()} was not registered in the verifier contracts."
            )
        return self.fact_memory_pages_map[fact_hash]

    def get_memory_pages_from_fact(self, fact_hash: bytes) -> List[List[int]]:
        """
        Given a fact hash, retrieves the memory pages which are relevant for that fact.
        """
        memory_pages = []
        memory_pages_hashes = self._get_memory_pages_hashes_from_fact(
            fact_hash)
        assert memory_pages_hashes is not None
        for memory_page_hash in memory_pages_hashes:
            transaction_str = self.memory_page_transactions_map[
                int.from_bytes(memory_page_hash, "big")
            ]
            memory_pages_tx = self.web3.eth.getTransaction(
                HexStr(transaction_str))
            inp = memory_pages_tx["input"]
            tx_decoded_values = self.memory_page_fact_registry_contract.decode_function_input(
                memory_pages_tx["input"]
            )[1]["values"]
            memory_pages.append(tx_decoded_values)
        return memory_pages


DEFAULT_GET_LOGS_MAX_CHUNK_SIZE = 10 ** 6


def get_contract_events(
    contract_event,
    from_block: int,
    to_block: int,
    get_logs_max_chunk_size: int = DEFAULT_GET_LOGS_MAX_CHUNK_SIZE,
) -> list:
    """
    Given a contract event and block numbers, retrieves a list of events in blocks
    [from_block, to_block).
    Splits the query in order to avoid Infura's maximal query limitation.
    See https://infura.io/docs/ethereum/json-rpc/eth_getLogs.
    """
    events = []
    assert from_block <= to_block
    split_queries_block_nums = list(
        range(from_block, to_block, get_logs_max_chunk_size))
    split_queries = [
        (query_from_block, query_to_block)
        for query_from_block, query_to_block in zip(
            split_queries_block_nums, split_queries_block_nums[1:] + [to_block]
        )
    ]
    for query_from_block, query_to_block in split_queries:
        events.extend(
            list(contract_event.getLogs(
                fromBlock=query_from_block, toBlock=query_to_block))
        )
    return events


def load_contracts(
    web3: web3.Web3, contracts_file: str, contracts_names: List[str]
) -> Dict[str, web3.contract.Contract]:
    """
    Given a list of contract names, returns a dict of contract names and contracts.
    """
    res = {}
    with open(contracts_file) as infile:
        source_json = json.load(infile)
    for contract_name in contracts_names:
        try:
            res[contract_name] = web3.eth.contract(
                address=source_json[contract_name]["address"], abi=source_json[contract_name]["abi"]
            )
        except (KeyError, InvalidAddress) as ex:
            raise ex
    return res


def parse_storage_updates(diffs):
    diffs.pop(0)  # num of contracts updates
    parsed_diff = {}
    while len(diffs) > 0:
        contract_address = hex(int(diffs.pop(0)))
        num_updates = diffs.pop(0)
        parsed_diff[contract_address] = {}
        for _ in range(num_updates):
            storage_var_address = hex(int(diffs.pop(0)))
            parsed_diff[contract_address][storage_var_address] = diffs.pop(0)
    return parsed_diff


def main():
    GOERLI_NODE = 'https://goerli.infura.io/v3/efaaed1253b8458abf2b8669ae9e9223'
    contract_names = ["GpsStatementVerifier", "MemoryPageFactRegistry"]
    parser = argparse.ArgumentParser()

    # Note that Registration of memory pages happens before the state update transaction, hence
    # make sure to use from_block which precedes (~500 blocks) the block of the state transition fact
    parser.add_argument('--from_block', dest='from_block', default=5742000,
                        help='find memory pages written after this block')
    parser.add_argument('--web3_node', dest='web3_node', default=GOERLI_NODE,
                        help='rpc node url')
    parser.add_argument('--contracts_abi_file', dest='contracts_abi_file', default="contracts.json",
                        help='name of the json file containing the abi of the GpsVerifier and MemoryPageFactRegistry')

    parser.add_argument('--fact', dest='fact', default="983e4a7350a46070642a1ba0e6df4b097d527633c1ef256a2140c9ad0f264587",
                        help='the fact whose associated memory pages will be returned')

    args = parser.parse_args()
    w3 = web3.Web3(web3.HTTPProvider(args.web3_node))
    assert w3.isConnected(
    ), f"Cannot connect to http provider {args.web3_node}."
    contracts_path = os.path.join(
        os.path.dirname(__file__), args.contracts_abi_file)
    contracts_dict = load_contracts(
        web3=w3, contracts_file=contracts_path, contracts_names=contract_names
    )
    (gps_statement_verifier_contract, memory_pages_contract) = [
        contracts_dict[contract_name] for contract_name in contract_names]
    memory_pages_fetcher = MemoryPagesFetcher.create(
        web3=w3,
        from_block=args.from_block,
        gps_statement_verifier_contract=gps_statement_verifier_contract,
        memory_page_fact_registry_contract=memory_pages_contract
    )
    pages = memory_pages_fetcher.get_memory_pages_from_fact(
        bytes.fromhex(args.fact))
    # Interpretation of pages
    state_diff = pages[1:]  # ignore first page
    diffs = [item for page in state_diff for item in page]  # flatten
    len_deployments = diffs.pop(0)
    deployments_data = list(map(lambda arg: hex(int(arg)) if int(
        arg) > 10**10 else int(arg), diffs[0:len_deployments]))
    storage_updates = parse_storage_updates(diffs[len_deployments:])
    deployed_contracts = {}
    while len(deployments_data) > 0:
        contract_address = deployments_data.pop(0)
        deployed_contracts[contract_address] = {}
        deployed_contracts[contract_address]['contract_hash'] = deployments_data.pop(
            0)
        num_constructor_args = deployments_data.pop(0)
        deployed_contracts[contract_address]['constructor arguments'] = deployments_data[0:num_constructor_args]
        deployments_data = deployments_data[num_constructor_args:]

    print(storage_updates)
    print(deployed_contracts)


if __name__ == "__main__":
    main()

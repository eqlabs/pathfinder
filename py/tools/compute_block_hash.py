import sys
import asyncio

from starkware.starknet.core.os.block_hash.block_hash import (
    calculate_event_hash,
    calculate_block_hash,
)
from starkware.starknet.services.api.feeder_gateway.response_objects import (
    StarknetBlock,
)
from starkware.starknet.definitions.general_config import (
    default_general_config,
    build_general_config,
)
from starkware.starknet.definitions.transaction_type import TransactionType


def main():
    """
    Given a file containing the JSON block compute the block hash using the `cairo-lang` implementation.
    """
    with open(sys.argv[1], encoding="utf-8") as f:
        general_config = build_general_config(default_general_config)
        block = StarknetBlock.loads(f.read())
        tx_hashes = [tx.transaction_hash for tx in block.transactions]
        tx_signatures = [
            tx.signature if tx.tx_type == TransactionType.INVOKE_FUNCTION else []
            for tx in block.transactions
        ]
        event_hashes = [
            calculate_event_hash(event.from_address, event.keys, event.data)
            for receipt in block.transaction_receipts
            for event in receipt.events
        ]

        block_hash = asyncio.run(
            calculate_block_hash(
                general_config=general_config,
                parent_hash=block.parent_block_hash,
                block_number=block.block_number,
                global_state_root=block.state_root,
                sequencer_address=0,
                block_timestamp=0,
                tx_hashes=tx_hashes,
                tx_signatures=tx_signatures,
                event_hashes=event_hashes,
            )
        )
        print(f"computed {block_hash} in block {block.block_hash}")


if __name__ == "__main__":
    main()

# reads stdin for a contract_definition json blob, writes a class hash to stdout
# example: python py/src/compute_class_hash.py < class_definition.json

from starkware.starknet.business_logic.fact_state.contract_state_objects import (
    ContractClassFact,
)
from starkware.starknet.services.api.contract_class import ContractClass
from starkware.cairo.lang.vm.crypto import pedersen_hash

import sys


def main():

    if len(sys.argv) != 1:
        print(
            "arguments are not accepted, this script reads stdin, writes a hash to stdout.",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.stdin.reconfigure(encoding="utf-8")
    contents = sys.stdin.read()

    cdf = ContractClassFact(ContractClass.loads(contents))

    print(cdf._hash(pedersen_hash).hex())
    sys.exit(0)


if __name__ == "__main__":
    main()

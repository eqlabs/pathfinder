# reads stdin for a contract_definition json blob, writes a class hash to stdout
# example: python py/src/compute_class_hash.py < class_definition.json

import sys

from starkware.cairo.lang.vm.crypto import pedersen_hash
from starkware.starknet.business_logic.fact_state.contract_class_objects import (
    DeprecatedCompiledClassFact,
)
from starkware.starknet.services.api.contract_class.contract_class import (
    DeprecatedCompiledClass,
)


def main():

    if len(sys.argv) != 1:
        print(
            "arguments are not accepted, this script reads stdin, writes a hash to stdout.",
            file=sys.stderr,
        )
        sys.exit(1)

    sys.stdin.reconfigure(encoding="utf-8")
    contents = sys.stdin.read()

    cdf = DeprecatedCompiledClassFact(DeprecatedCompiledClass.loads(contents))

    print(cdf._hash(pedersen_hash).hex())
    sys.exit(0)


if __name__ == "__main__":
    main()

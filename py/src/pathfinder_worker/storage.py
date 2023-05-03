import json
import sqlite3
from typing import Optional

import zstandard
from starkware.starknet.business_logic.state.state_api import StateReader
from starkware.starknet.definitions import fields
from starkware.starknet.definitions.error_codes import StarknetErrorCode
from starkware.starknet.services.api.contract_class.contract_class import (
    CompiledClass,
    CompiledClassBase,
    DeprecatedCompiledClass,
)
from starkware.starkware_utils.error_handling import StarkException


class SqliteStateReader(StateReader):
    """
    A StateReader implementation that reads from the SQLite database of pathfinder.
    """

    def __init__(self, connection: sqlite3.Connection, block_number: int):
        assert (
            connection.in_transaction
        ), "first query should have started a transaction"
        self.connection = connection
        self.block_number = block_number

    # StateReader API
    async def get_compiled_class(self, compiled_class_hash: int) -> CompiledClassBase:
        # Compiled_class_hash is either the hash of a compiled CASM _or_ the class hash
        # of a Cairo 0.x class. The order matters here, because if there is no CASM
        # definition the class is guaranteed to be a deprecated class (if exists).
        class_definition = self._get_compiled_class(
            compiled_class_hash
        ) or self._get_deprecated_class(compiled_class_hash)

        if class_definition is None:
            formatted_class_hash = fields.ClassHashIntField.format(compiled_class_hash)
            raise StarkException(
                code=StarknetErrorCode.UNDECLARED_CLASS,
                message=f"Class with hash {formatted_class_hash} is not declared.",
            )

        return class_definition

    async def get_compiled_class_hash(self, class_hash: int) -> int:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                compiled_class_hash
            FROM
                casm_definitions
            WHERE
                hash = ?
            """,
            [felt_to_bytes(class_hash)],
        )
        row = res.fetchone()
        if row is None:
            return 0

        compiled_class_hash = row[0]
        compiled_class_hash = int.from_bytes(compiled_class_hash, byteorder="big")

        return compiled_class_hash

    async def get_class_hash_at(self, contract_address: int) -> int:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                class_hash
            FROM
                contract_updates
            WHERE
                contract_address = ?
                AND
                block_number <= ?
            ORDER BY block_number
            DESC
            LIMIT 1
            """,
            [felt_to_bytes(contract_address), self.block_number],
        )
        row = res.fetchone()
        if row is None:
            return 0

        class_hash = row[0]
        class_hash = int.from_bytes(class_hash, byteorder="big")

        return class_hash

    async def get_nonce_at(self, contract_address: int) -> int:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                nonce
            FROM
                nonce_updates
            WHERE
                contract_address = ?
                AND
                block_number <= ?
            ORDER BY block_number
            DESC
            LIMIT 1
            """,
            [felt_to_bytes(contract_address), self.block_number],
        )
        row = res.fetchone()
        if row is None:
            return 0

        nonce = row[0]
        nonce = int.from_bytes(nonce, byteorder="big")

        return nonce

    async def get_storage_at(self, contract_address: int, key: int) -> int:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                storage_value
            FROM
                storage_updates
            WHERE
                contract_address = ?
                AND
                storage_address = ?
                AND
                block_number <= ?
            ORDER BY block_number
            DESC
            LIMIT 1
            """,
            [felt_to_bytes(contract_address), felt_to_bytes(key), self.block_number],
        )
        row = res.fetchone()
        if row is None:
            return 0

        value = row[0]
        value = int.from_bytes(value, byteorder="big")

        return value

    def _get_deprecated_class(
        self, class_hash: int
    ) -> Optional[DeprecatedCompiledClass]:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                definition
            FROM
                class_definitions
            WHERE
                hash = ?
            """,
            [felt_to_bytes(class_hash)],
        )
        row = res.fetchone()
        if row is None:
            return None

        class_definition = row[0]
        class_definition = zstandard.decompress(class_definition)
        class_definition = json.loads(class_definition)
        class_definition = DeprecatedCompiledClass.load(class_definition)

        return class_definition

    def _get_compiled_class(self, class_hash: int) -> Optional[CompiledClass]:
        cursor = self.connection.cursor()
        res = cursor.execute(
            """
            SELECT
                definition
            FROM
                casm_definitions
            WHERE
                compiled_class_hash = ?
            """,
            [felt_to_bytes(class_hash)],
        )
        row = res.fetchone()
        if row is None:
            return None

        class_definition = row[0]
        class_definition = zstandard.decompress(class_definition)
        class_definition = json.loads(class_definition)
        class_definition = CompiledClass.load(class_definition)

        return class_definition


def felt_to_bytes(v: int) -> bytes:
    return v.to_bytes(length=32, byteorder="big")

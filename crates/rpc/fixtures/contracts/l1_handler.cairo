#[starknet::contract]
mod TestContract {
    #[storage]
    struct Storage {
        my_storage_var: felt252
    }

    #[l1_handler]
    fn my_l1_handler(ref self: ContractState, from_address: felt252, value: felt252) {
        self.my_storage_var.write(value);
    }
}


#[starknet::contract]
mod TestContract {
    #[storage]
    struct Storage {
        my_storage_var: felt252
    }

    #[external(v0)]
    fn set_data(ref self: ContractState, value: felt252) {
        self.my_storage_var.write(value);
    }

    #[external(v0)]
    fn get_data(self: @ContractState) -> felt252 {
        self.my_storage_var.read()
    }
}


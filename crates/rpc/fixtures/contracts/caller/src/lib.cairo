use starknet::account::Call;

#[starknet::interface]
pub trait ICaller<TContractState> {
    fn call(ref self: TContractState, calls: Array<Call>) -> Array<Span<felt252>>;
}

#[starknet::contract]
pub mod Caller {
    use starknet::account::Call;
    use starknet::SyscallResultTrait;
    
    #[storage]
    struct Storage {}

    #[abi(embed_v0)]
    pub impl CallerImpl of super::ICaller<ContractState> {        
        fn call(ref self: ContractState, calls: Array<Call>) -> Array<Span<felt252>> {
            let mut res = array![];
            for call in calls.span() {
                res.append(execute_single_call(call))
            };
            res
        }        
    }

    fn execute_single_call(call: @Call) -> Span<felt252> {
        let Call { to, selector, calldata } = *call;
        starknet::syscalls::call_contract_syscall(to, selector, calldata).unwrap_syscall()
    }
}

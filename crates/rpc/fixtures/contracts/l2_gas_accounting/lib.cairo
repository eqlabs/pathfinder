/// Simple contract for managing balance.
#[starknet::contract]
mod HelloStarknet {

    use core::poseidon::{hades_permutation};
    #[storage]
    struct Storage {}

    #[abi(per_item)]
    #[generate_trait]
    impl SomeImpl of SomeTrait {
        #[external(v0)]
        fn test_stack_overflow(ref self: ContractState, depth: u128) -> u128 {
            non_trivial_recursion(depth)
        }
        
        #[external(v0)]
        fn test_redeposits(ref self:ContractState, depth: u128) -> felt252 {
            if(depth == 0) {
                return 0;
            }
            let res = self.test_redeposits(depth-1);
            // should be redeposited for the large if since res is never != 0
            if(res != 0) {
                let mut tup = hades_permutation(1,2,3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                let (s1,s2,s3) = tup;
                tup = hades_permutation(s1,s2,s3);
                s1
            }
            else {
                res
            }
        }
    }

    fn non_trivial_recursion(depth: u128) -> u128 {
        non_trivial_recursion(depth - 1) + 2 * non_trivial_recursion(depth - 2)
    }
}

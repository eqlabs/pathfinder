macro_rules! derive_op {
    ($type:ident,$iface:ident, $fun:ident, $op:tt) => {
        impl std::ops::$iface<Self> for $type {
            type Output = $type;
            fn $fun(self, rhs: Self) -> Self::Output {
                $type(self.0 $op rhs.0)
            }
        }
        impl std::ops::$iface<&Self> for $type {
            type Output = $type;
            fn $fun(self, rhs: &Self) -> Self::Output {
                $type(self.0 $op &rhs.0)
            }
        }
        impl std::ops::$iface<&mut Self> for $type {
            type Output = $type;
            fn $fun(self, rhs: &mut Self) -> Self::Output {
                $type(self.0 $op &rhs.0)
            }
        }
        impl std::ops::$iface<$type> for &$type {
            type Output = $type;
            fn $fun(self, rhs: $type) -> Self::Output {
                $type(self.0.clone() $op rhs.0)
            }
        }
        impl std::ops::$iface<&$type> for &$type {
            type Output = $type;
            fn $fun(self, rhs: &$type) -> Self::Output {
                $type(self.0.clone() $op &rhs.0)
            }
        }
        impl std::ops::$iface<&mut $type> for &$type {
            type Output = $type;
            fn $fun(self, rhs: &mut $type) -> Self::Output {
                $type(self.0.clone() $op &rhs.0)
            }
        }
    };
}
pub(crate) use derive_op;

macro_rules! derive_op_assign {
    ($type:ident, $iface:ident, $fun:ident,$op:tt) => {
        impl std::ops::$iface<Self> for $type {
            fn $fun(&mut self, rhs: Self) {
                self.0 $op rhs.0;
            }
        }
        impl std::ops::$iface<&Self> for $type {
            fn $fun(&mut self, rhs: &Self) {
                self.0 $op &rhs.0;
            }
        }
        impl std::ops::$iface<&mut Self> for $type {
            fn $fun(&mut self, rhs: &mut Self) {
                self.0 $op &rhs.0;
            }
        }
    };
}
pub(crate) use derive_op_assign;

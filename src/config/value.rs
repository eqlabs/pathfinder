use derive_more::{From, IsVariant, TryInto};
use reqwest::Url;
use std::net::IpAddr;

#[derive(Debug, Clone, PartialEq, Eq, From, IsVariant, TryInto)]
#[try_into(owned, ref, ref_mut)]
pub enum Value {
    #[try_into(ignore)]
    None,
    Bool(bool),
    IpAddr(IpAddr),
    String(String),
    U16(u16),
    Url(Url),
}

impl<T> From<Option<T>> for Value
where
    Value: From<T>,
{
    fn from(optional: Option<T>) -> Self {
        match optional {
            Some(t) => Value::from(t),
            None => Self::None,
        }
    }
}

serde_with::serde_conv!(
    pub IpAddrAsString,
    IpAddr,
    |a: &IpAddr| *a,
    |s: String| -> Result<_, _> { s.parse::<IpAddr>() }
);

serde_with::serde_conv!(
    pub UrlAsString,
    Url,
    |u: &Url| u.to_string(),
    |s: String| -> Result<_, _> { s.parse::<Url>() }
);

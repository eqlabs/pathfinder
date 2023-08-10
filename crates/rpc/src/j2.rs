// #![allow(dead_code)]

// use std::collections::HashMap;
// use std::marker::PhantomData;

// use futures::Future;
// use serde::de::DeserializeOwned;
// use serde_json::Value;

// use crate::context::RpcContext;

// #[derive(Default)]
// struct MethodRouter {
//     methods: HashMap<&'static str, Box<dyn Method>>,
// }

// impl MethodRouter {
//     fn register<I>(
//         mut self,
//         method_name: &'static str,
//         method: impl IntoMethod<I> + 'static,
//     ) -> Self {
//         self.methods.insert(method_name, method.into_method());
//         self
//     }

//     async fn invoke(
//         &self,
//         method: &str,
//         input: Value,
//         state: RpcContext,
//     ) -> Result<Value, crate::jsonrpc::RpcError> {
//         match self.methods.get(method) {
//             Some(method) => method.invoke(input, state).await.map_err(Into::into),
//             None => Err(crate::jsonrpc::RpcError::MethodNotFound {
//                 method: method.to_owned(),
//             }),
//         }
//     }
// }

// #[axum::async_trait]
// trait Method {
//     async fn invoke(
//         &self,
//         input: Value,
//         state: RpcContext,
//     ) -> Result<Value, crate::error::RpcError>;
// }

// trait IntoMethod<I> {
//     fn into_method(self) -> Box<dyn Method>;
// }

// /// impl for 
// /// () -> T
// /// input only
// /// state only
// /// input and state



// impl<'de, Func, Fut, Input> IntoMethod<((), Input)> for Func
// where
//     Func: Fn(Input) -> Fut + Clone + 'static + std::marker::Sync + std::marker::Send,
//     Fut: Future<Output = u32> + std::marker::Send + 'static,
//     Input: DeserializeOwned + std::marker::Sync + std::marker::Send + 'static,
// {
//     fn into_method(self) -> Box<dyn Method> {
//         struct HandlerImpl<Func, Fut, Input>
//         where
//             Func: Fn(Input) -> Fut + Clone,
//             Fut: Future<Output = u32>,
//         {
//             f: Func,
//             _marker: PhantomData<Input>,
//         }

//         #[axum::async_trait]
//         impl<'de, Func, Fut, Input> Method for HandlerImpl<Func, Fut, Input>
//         where
//             Func: Fn(Input) -> Fut + Clone + 'static + std::marker::Sync + std::marker::Send,
//             Fut: Future<Output = u32> + std::marker::Send,
//             Input: DeserializeOwned + std::marker::Sync + std::marker::Send + 'static,
//         {
//             async fn invoke(&self, input: Value) -> u32 {
//                 let input: Input = serde_json::from_value(input).unwrap();
//                 let f = self.f.clone();
//                 async move { f(input).await }.await
//             }
//         }

//         Box::new(HandlerImpl {
//             f: self,
//             _marker: Default::default(),
//         }) as Box<dyn Method>
//     }
// }

// impl<Func, Fut> IntoMethod<u32> for Func
// where
//     Func: Fn(u32) -> Fut + Clone + 'static + std::marker::Sync + std::marker::Send,
//     Fut: Future<Output = u32> + std::marker::Send + 'static,
// {
//     fn into_method(self) -> Box<dyn Method> {
//         struct HandlerImpl<Func, Fut>
//         where
//             Func: Fn(u32) -> Fut + Clone,
//             Fut: Future<Output = u32>,
//         {
//             f: Func,
//         }

//         #[derive(serde::Deserialize)]
//         struct Input(u32);

//         #[axum::async_trait]
//         impl<Func, Fut> Method for HandlerImpl<Func, Fut>
//         where
//             Func: Fn(u32) -> Fut + Clone + std::marker::Sync + std::marker::Send,
//             Fut: Future<Output = u32> + std::marker::Send,
//         {
//             async fn invoke(&self, input: Value) -> u32 {
//                 let input: Input = serde_json::from_value(input).unwrap();
//                 let f = self.f.clone();
//                 f(input.0).await
//             }
//         }

//         Box::new(HandlerImpl { f: self }) as Box<dyn Method>
//     }
// }

// impl<Func> IntoMethod<()> for Func
// where
//     Func: Fn() -> Value + Clone + 'static + std::marker::Sync,
// {
//     fn into_method(self) -> Box<dyn Method> {
//         struct HandlerImpl<Func: Fn() -> u32 + Clone> {
//             f: Func,
//         }

//         #[axum::async_trait]
//         impl<Func: Fn() -> u32 + Clone + std::marker::Sync> Method for HandlerImpl<Func> {
//             async fn invoke(&self, _input: Value) -> u32 {
//                 let f = self.f.clone();
//                 f()
//             }
//         }

//         Box::new(HandlerImpl { f: self }) as Box<dyn Method>
//     }
// }

// #[tokio::test]
// async fn feature() {
//     async fn echo(x: u32) -> u32 {
//         x
//     }

//     fn always_10() -> u32 {
//         10
//     }

//     async fn double(x: u32) -> u32 {
//         x * 2
//     }

//     #[derive(serde::Deserialize)]
//     struct In(u32);

//     async fn echo_serde(input: In) -> u32 {
//         input.0
//     }

//     let router = MethodRouter::default()
//         .register::<u32>("echo", echo)
//         .register("always_10", always_10)
//         .register::<u32>("double", double)
//         .register("echo_serde", echo_serde);

//     let input = Value::Number(20.into());

//     assert_eq!(router.invoke("echo_serde", input.clone()).await, 20);
//     assert_eq!(router.invoke("echo", input.clone()).await, 20);
//     assert_eq!(router.invoke("always_10", input.clone()).await, 10);
//     assert_eq!(router.invoke("double", input).await, 20 * 2);
// }

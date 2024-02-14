use proc_macro2::{TokenStream, TokenTree};
use quote::{quote, quote_spanned};
use syn::{parse_macro_input, spanned::Spanned, Data, DeriveInput};

#[proc_macro_derive(ToProtobuf, attributes(protobuf))]
pub fn derive_to_protobuf(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    derive_to_protobuf_impl(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn derive_to_protobuf_impl(input: DeriveInput) -> Result<proc_macro2::TokenStream, syn::Error> {
    let name = input.ident;
    let protobuf_type_path = parse_attribute(&input.attrs, &name)?;

    let fields = iterate_to_protobuf(&input.data)?;

    Ok(quote! {
        impl crate::ToProtobuf<#protobuf_type_path> for #name {
            #[allow(clippy::useless_conversion)]
            fn to_protobuf(self) -> #protobuf_type_path {
                #protobuf_type_path {
                    #fields
                }
            }
        }
    })
}

/// Parse the "protobuf" attribute of our type.
///
/// Returns the type path for the protobuf-generated type we should use in the
/// implementation of the conversion.
fn parse_attribute(
    attrs: &[syn::Attribute],
    name: &syn::Ident,
) -> Result<syn::TypePath, syn::Error> {
    let mut protobuf_type_name = format!("crate::proto::{name}");

    // Find matching attribute and parse the "name" parameter as a string
    for attr in attrs {
        if attr.path.is_ident("protobuf") {
            match attr.parse_meta() {
                Ok(syn::Meta::List(meta)) => {
                    for meta_item in meta.nested.iter() {
                        match meta_item {
                            syn::NestedMeta::Meta(syn::Meta::NameValue(m))
                                if m.path.is_ident("name") =>
                            {
                                if let syn::Lit::Str(lit) = &m.lit {
                                    protobuf_type_name = lit.value();
                                }
                            }
                            _ => {
                                return Err(syn::Error::new(
                                    meta_item.span(),
                                    "expected name-value pairs",
                                ))
                            }
                        }
                    }
                }
                Ok(_) => {
                    return Err(syn::Error::new(
                        attr.span(),
                        "expected a list of name-value pairs",
                    ))
                }
                Err(_) => {
                    return Err(syn::Error::new(
                        attr.span(),
                        "failed to parse content of the attribute",
                    ))
                }
            }
        }
    }

    // Parse string form of the type name into a type path
    let protobuf_type_name_stream: proc_macro2::TokenStream = syn::parse_str(&protobuf_type_name)?;
    let protobuf_type_path: syn::TypePath = syn::parse2(protobuf_type_name_stream)?;

    Ok(protobuf_type_path)
}

/// Iterates over named fields and calls `ToProtobuf::to_protobuf()` on each.
fn iterate_to_protobuf(data: &Data) -> Result<proc_macro2::TokenStream, syn::Error> {
    match *data {
        Data::Struct(ref data) => match data.fields {
            syn::Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let name_in_proto = get_field_name_in_proto(f).or(name.clone());
                    quote_spanned! {f.span()=>
                        #name_in_proto: crate::ToProtobuf::to_protobuf(self.#name).into()
                    }
                });
                Ok(quote! {
                    #(#recurse),*
                })
            }
            syn::Fields::Unit => Ok(Default::default()),
            syn::Fields::Unnamed(_) => {
                Err(syn::Error::new(data.fields.span(), "expected named struct"))
            }
        },
        Data::Enum(ref e) => Err(syn::Error::new(
            e.enum_token.span(),
            "expected named struct, got enum",
        )),
        Data::Union(ref u) => Err(syn::Error::new(
            u.union_token.span(),
            "expected named struct, got union",
        )),
    }
}

#[proc_macro_derive(TryFromProtobuf, attributes(optional, rename))]
pub fn derive_try_from_protobuf(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    derive_try_from_protobuf_impl(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn derive_try_from_protobuf_impl(
    input: DeriveInput,
) -> Result<proc_macro2::TokenStream, syn::Error> {
    let name = input.ident;
    let protobuf_type_path = parse_attribute(&input.attrs, &name)?;

    let fields = iterate_try_from_protobuf(&input.data)?;

    Ok(quote! {
        impl crate::TryFromProtobuf<#protobuf_type_path> for #name {
            fn try_from_protobuf(input: #protobuf_type_path, field_name: &'static str) -> Result<Self, std::io::Error> {
                Ok(Self {
                    #fields
                })
            }
        }
    })
}

fn iterate_try_from_protobuf(data: &Data) -> Result<proc_macro2::TokenStream, syn::Error> {
    match *data {
        Data::Struct(ref data) => match data.fields {
            syn::Fields::Named(ref fields) => {
                let recurse = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    let is_optional = f.attrs.iter().any(|a| a.path.is_ident("optional"));
                    let name_in_proto = get_field_name_in_proto(f).or(name.clone());

                    if is_optional {
                        quote_spanned! {f.span()=>
                            #name: match input.#name_in_proto {
                                Some(x) => Some(crate::TryFromProtobuf::try_from_protobuf(x, stringify!(#name_in_proto))?),
                                None => None,
                            }
                        }
                    } else {
                        quote_spanned! {f.span()=>
                            #name: crate::TryFromProtobuf::try_from_protobuf(input.#name_in_proto, stringify!(#name_in_proto))?
                        }
                    }
                });
                Ok(quote! {
                    #(#recurse),*
                })
            }
            syn::Fields::Unit => Ok(Default::default()),
            syn::Fields::Unnamed(_) => {
                Err(syn::Error::new(data.fields.span(), "expected named struct"))
            }
        },
        Data::Enum(ref e) => Err(syn::Error::new(
            e.enum_token.span(),
            "expected named struct, got enum",
        )),
        Data::Union(ref u) => Err(syn::Error::new(
            u.union_token.span(),
            "expected named struct, got union",
        )),
    }
}

/// Returns the original name of the field in the protobuf struct which is specified by the `#[rename(original_name)]` attribute.
///
/// ```
/// // crate::proto, generated by `prost`
/// pub struct Y {
///    pub original_name: u32,
/// }
///
/// // crate::our
/// #[derive(ToProtobuf, TryFromProtobuf)]
/// #[protobuf(name = "crate::proto::Y")]
/// pub struct X {
///    #[rename(original_name)]
///    pub new_name: u32,
/// }
/// ```
///
fn get_field_name_in_proto(f: &syn::Field) -> Option<proc_macro2::Ident> {
    f.attrs.iter().find_map(|a| {
        if a.path.is_ident("rename") {
            let tt = try_into_one_token_tree(a.tokens.clone());
            match tt {
                Some(proc_macro2::TokenTree::Group(g)) => match try_into_one_token_tree(g.stream())
                {
                    Some(proc_macro2::TokenTree::Ident(i)) => Some(i),
                    Some(_) | None => None,
                },
                Some(_) | None => None,
            }
        } else {
            None
        }
    })
}

fn try_into_one_token_tree(stream: TokenStream) -> Option<TokenTree> {
    let mut it = stream.into_iter();
    let token = it.next();
    if it.next().is_some() {
        None
    } else {
        token
    }
}

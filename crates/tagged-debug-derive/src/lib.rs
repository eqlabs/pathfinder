use std::convert::From;

use proc_macro2::Ident;
use quote::{format_ident, quote, quote_spanned};
use syn::spanned::Spanned;
use syn::{parse_macro_input, Data, DeriveInput};

#[proc_macro_derive(TaggedDebug)]
pub fn derive_tagged_debug(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = parse_macro_input!(input as DeriveInput);

    derive_tagged_debug_impl(input)
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

fn derive_tagged_debug_impl(input: DeriveInput) -> Result<proc_macro2::TokenStream, syn::Error> {
    let name = input.ident;
    let fmt_body = iterate_tagged_debug(&name, &input.data)?;

    Ok(quote! {
        impl std::fmt::Debug for #name {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                #fmt_body
            }
        }
    })
}

fn iterate_tagged_debug(name: &Ident, data: &Data) -> Result<proc_macro2::TokenStream, syn::Error> {
    match *data {
        Data::Struct(ref data) => Ok(iterate_struct_fields(name, &data.fields)),
        Data::Enum(ref e) => Ok(iterate_enum_variants(name, &e.variants)),
        Data::Union(ref u) => Err(syn::Error::new(
            u.union_token.span(),
            "union is not supported",
        )),
    }
}

fn iterate_struct_fields(struct_name: &Ident, fields: &syn::Fields) -> proc_macro2::TokenStream {
    match fields {
        syn::Fields::Named(ref fields) => {
            let fields = fields.named.iter().map(|f| {
                let name = &f.ident;
                quote_spanned! {f.span()=>
                    .field(stringify!(#name), &self.#name)
                }
            });
            let fields_clone = fields.clone();
            quote! {
                match Tagged::<#struct_name>::tag(self) {
                    Ok(tag) => {
                        f.debug_struct(stringify!(#struct_name))
                            .field("TAG", &tag)
                            #(#fields)*
                            .finish()
                    }
                    Err(_) => {
                        f.debug_struct(stringify!(#struct_name))
                            #(#fields_clone)*
                            .finish()
                    }
                }
            }
        }
        syn::Fields::Unit => quote! {
            match Tagged::<#struct_name>::tag(self) {
                Ok(tag) => {
                    f.debug_struct(stringify!(#struct_name))
                        .field("TAG", &tag)
                        .finish()
                }
                Err(_) => {
                    f.debug_struct(stringify!(#struct_name))
                        .finish()
                }
            }
        },
        syn::Fields::Unnamed(ref fields) => {
            let fields = fields.unnamed.iter().enumerate().map(|(i, f)| {
                let i = syn::Index::from(i);
                quote_spanned! {f.span()=>
                    .field(&self.#i)
                }
            });
            let fields_clone = fields.clone();
            quote! {
                match Tagged::<#struct_name>::tag(self) {
                    Ok(tag) => {
                        f.debug_tuple(stringify!(#struct_name))
                            .field(&format!("TAG: {}", &tag))
                            #(#fields)*
                            .finish()
                    }
                    Err(_) => {
                        f.debug_tuple(stringify!(#struct_name))
                            #(#fields_clone)*
                            .finish()
                    }
                }
            }
        }
    }
}

fn iterate_enum_variants(
    enum_name: &Ident,
    variants: &syn::punctuated::Punctuated<syn::Variant, syn::token::Comma>,
) -> proc_macro2::TokenStream {
    let variant_impls = variants.iter().map(|v| {
        let variant_name = &v.ident;

        match v.fields {
            syn::Fields::Named(ref fields) => {
                let fields_pattern = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        #name,
                    }
                });

                let fields_impl = fields.named.iter().map(|f| {
                    let name = &f.ident;
                    quote_spanned! {f.span()=>
                        .field(stringify!(#name), &#name)
                    }
                });
                let fields_impl_clone = fields_impl.clone();

                quote! {
                    #enum_name::#variant_name {
                        #(#fields_pattern)*
                    } => {
                    match Tagged::<#enum_name>::tag(self) {
                        Ok(tag) => {
                            f.debug_struct(stringify!(#variant_name))
                            .field("TAG", &tag)
                            #(#fields_impl)*
                            .finish()
                        }
                        Err(_) => {
                            f.debug_struct(stringify!(#variant_name))
                            #(#fields_impl_clone)*
                            .finish()
                        }
                    }}
                }
            }
            syn::Fields::Unit => quote! {
                #enum_name::#variant_name => {
                match Tagged::<#enum_name>::tag(self) {
                    Ok(tag) => {
                        f.debug_struct(stringify!(#variant_name))
                        .field("TAG", &tag)
                        .finish()
                    }
                    Err(_) => {
                        f.debug_struct(stringify!(#variant_name))
                        .finish()
                    }
                }}
            },
            syn::Fields::Unnamed(ref fields) => {
                let fields_pattern = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let i = syn::Index::from(i);
                    let field_name = format_ident!("field_{}", i);

                    quote_spanned! {f.span()=>
                        #field_name,
                    }
                });

                let fields_impl = fields.unnamed.iter().enumerate().map(|(i, f)| {
                    let i = syn::Index::from(i);
                    let field_name = format_ident!("field_{}", i);

                    quote_spanned! {f.span()=>
                        .field(&#field_name)
                    }
                });
                let fields_impl_clone = fields_impl.clone();

                quote! {
                    #enum_name::#variant_name (
                        #(#fields_pattern)*
                    ) => {
                    match Tagged::<#enum_name>::tag(self) {
                        Ok(tag) => {
                            f.debug_tuple(stringify!(#variant_name))
                            .field(&format!("TAG: {}", &tag))
                            #(#fields_impl)*
                            .finish()
                        }
                        Err(_) => {
                            f.debug_tuple(stringify!(#variant_name))
                            #(#fields_impl_clone)*
                            .finish()
                        }
                    }}
                }
            }
        }
    });
    quote! {
        match self {
            #(#variant_impls)*
        }
    }
}

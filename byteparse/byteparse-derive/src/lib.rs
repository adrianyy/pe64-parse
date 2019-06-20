extern crate proc_macro;

use proc_macro::TokenStream;
use syn::parse_macro_input;

#[proc_macro_derive(Byteparse)]
pub fn byte_parse(input: TokenStream) -> TokenStream {
    let input = parse_macro_input!(input as syn::DeriveInput);

    if let syn::Data::Struct(syn::DataStruct { fields, .. }) = &input.data {
        let members = fields.iter()
            .enumerate()
            .map(|(i, f)| {
                if let Some(ident) = &f.ident {
                    ident.to_string()
                } else {
                    format!("{}", i)
                }
            });

        let mut o = format!("unsafe impl Byteparse for {} {{", input.ident);
        o += "fn parse_to<R>(&mut self, r: &mut R) -> ::std::io::Result<()>";
        o += "    where R: ::std::io::Read {";
        
        for m in members {
            o += &format!(
                "::byteparse::Byteparse::parse_to(&mut self.{}, r)?;", m);
        }

        o += "Ok(()) }}";

        return o.parse().expect("Invalid syntax, macro error.");
    }

    panic!("Invalid input structure");
}

extern crate proc_macro;

/// Create Byteparse implementation for given structure.
#[proc_macro_derive(Byteparse)]
pub fn byteparse(input: proc_macro::TokenStream) -> proc_macro::TokenStream {
    let input = syn::parse_macro_input!(input as syn::DeriveInput);

    if let syn::Data::Struct(syn::DataStruct { fields, .. }) = &input.data {
        // Get name of all struct members.
        let members = fields.iter()
            .enumerate()
            .map(|(i, f)| {
                // In named structs we use names. In tuple structs
                // we use indices.
                if let Some(ident) = &f.ident {
                    ident.to_string()
                } else {
                    format!("{}", i)
                }
            });

        // Implement Byteparse trait for given struct.
        let mut o = format!(
            "unsafe impl ::byteparse::Byteparse for {} {{", input.ident);
        o += "fn parse_to<R>(&mut self, r: &mut R) -> ::std::io::Result<()>";
        o += "    where R: ::std::io::Read {";
        
        // Parse every member individually.
        for m in members {
            o += &format!(
                "::byteparse::Byteparse::parse_to(&mut self.{}, r)?;", m);
        }

        // Return success and close function.
        o += "::std::result::Result::Ok(())";
        o += "}}";

        return o.parse().expect("Invalid syntax, macro error.");
    }

    // Only structs are valid input for this macro.
    panic!("Invalid input structure");
}
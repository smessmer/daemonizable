//! Proc-macro companion crate for `daemonizable`. Don't depend on this crate
//! directly — the `daemonizable` crate re-exports [`macro@main`] behind its
//! default-on `macros` feature.

use proc_macro::TokenStream;
use quote::quote;
use syn::spanned::Spanned;

/// Attach to your `impl Daemonizable for YourApp` block to generate the
/// `main` function. This is the recommended way to build a `daemonizable`
/// application.
///
/// Expands to the unchanged impl plus
/// `fn main() -> ExitCode { daemonizable::run::<YourApp>() }` — the whole
/// `main` an application built on `daemonizable` should have. Writing that
/// line by hand is easy to get subtly wrong (extra work before `run` — which
/// the re-exec'd daemon child then runs too — or a swallowed exit code); the
/// attribute makes the correct shape the default.
///
/// `src/main.rs`:
///
/// ```ignore
/// use std::process::ExitCode;
///
/// use daemonizable::{Daemonizable, Daemonizer, RpcServer};
///
/// struct MyApp;
///
/// #[daemonizable::main]
/// impl Daemonizable for MyApp {
///     type Request = String;
///     type Response = String;
///
///     fn build_id() -> String {
///         format!("my-app {}", env!("CARGO_PKG_VERSION"))
///     }
///
///     fn run_foreground(daemonizer: Daemonizer<Self>) -> ExitCode {
///         let mut rpc = daemonizer.spawn_daemon().unwrap();
///         rpc.send_request(&"hello".to_string()).unwrap();
///         println!("daemon says: {}", rpc.recv_response_blocking().unwrap());
///         ExitCode::SUCCESS
///     }
///
///     fn run_daemon(mut rpc: RpcServer<String, String>) -> ! {
///         while let Ok(request) = rpc.next_request() {
///             rpc.send_response(&format!("echo: {request}")).unwrap();
///         }
///         std::process::exit(0)
///     }
/// }
/// ```
///
/// (The fence is `ignore`, not a compiled doctest: this crate cannot depend on
/// `daemonizable` — that would be a dependency cycle — so the types above are
/// not in scope here. The macro's real expansion is covered by the trybuild
/// cases in `daemonizable-e2e-tests/tests/macro_ui/` — which compile and run
/// `#[daemonizable::main]` programs through the real macro — and a compiled
/// equivalent of the hand-written-`main` shape is the doctest on
/// `daemonizable::run`.)
///
/// # Requirements
///
/// - Apply it **at the crate root of a bin target**: the attribute emits
///   `fn main` right next to the impl, so inside a module the function would
///   land in that module instead of the crate root (rustc then reports a
///   missing `main` without pointing here — a limitation the macro cannot
///   detect).
/// - The trait is matched **syntactically by name**: the impl's trait path
///   must end in the segment `Daemonizable` (so `impl Daemonizable for X`
///   and `impl daemonizable::Daemonizable for X` both work, but a
///   `use daemonizable::Daemonizable as D` rename is rejected — and a
///   foreign trait that happens to be named `Daemonizable` would be
///   accepted here and only fail type-checking on the generated
///   `run::<X>()` call).
/// - Generic impls are not supported: `run` needs one concrete application
///   type to dispatch on.
/// - The generated `main` calls `::daemonizable::run` by default, so the
///   dependency must be named exactly `daemonizable` in Cargo.toml. If you
///   rename it (`dz = { package = "daemonizable", ... }`), tell the macro
///   with the attribute's one supported argument —
///   `#[dz::main(crate = "dz")]` — which substitutes that path in the
///   emitted `main` (the same escape hatch as `#[tokio::main(crate = ...)]`
///   / `#[serde(crate = ...)]`). Without it the generated body fails with
///   E0433 "unresolved crate or module `daemonizable`" anchored at the
///   attribute invocation.
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = proc_macro2::TokenStream::from(item);
    match expand(attr.into(), item.clone()) {
        Ok(expanded) => expanded.into(),
        Err(err) => {
            // Re-emitted alongside the error so the item stays alive and the
            // caller sees our diagnostic instead of a cascade of unresolved names.
            let err = err.to_compile_error();
            quote!( #item #err ).into()
        }
    }
}

/// Parse the attribute arguments: either nothing (→ the default
/// `::daemonizable` path) or exactly `crate = "some::path"` naming the crate
/// the generated `main` should call `run` on — the escape hatch for a renamed
/// dependency. Anything else is rejected with a single crisp error.
fn parse_crate_path(attr: proc_macro2::TokenStream) -> syn::Result<syn::Path> {
    const USAGE: &str = "#[daemonizable::main] supports only the `crate = \"...\"` argument, e.g. \
         #[dz::main(crate = \"dz\")] for a dependency renamed to `dz`";
    if attr.is_empty() {
        // Leading `::` so the expansion always names the external crate, never
        // a same-named module in the user's crate root.
        return Ok(syn::parse_quote!(::daemonizable));
    }
    let span = attr.span();
    let nv: syn::MetaNameValue = syn::parse2(attr).map_err(|_| syn::Error::new(span, USAGE))?;
    if !nv.path.is_ident("crate") {
        return Err(syn::Error::new_spanned(&nv.path, USAGE));
    }
    match nv.value {
        syn::Expr::Lit(syn::ExprLit {
            lit: syn::Lit::Str(s),
            ..
        }) => s.parse::<syn::Path>().map_err(|_| {
            syn::Error::new_spanned(
                &s,
                "crate = \"...\" must contain a path to the daemonizable crate, e.g. \
                 crate = \"dz\" or crate = \"my_facade::daemonizable\"",
            )
        }),
        other => Err(syn::Error::new_spanned(&other, USAGE)),
    }
}

fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    let crate_path = parse_crate_path(attr)?;

    let item_impl: syn::ItemImpl = syn::parse2(item.clone()).map_err(|_| {
        syn::Error::new(
            item.span(),
            "#[daemonizable::main] must be attached to an `impl Daemonizable for YourApp` block",
        )
    })?;

    let is_daemonizable_impl = item_impl
        .trait_
        .as_ref()
        .and_then(|(path, _)| path.segments.last())
        .is_some_and(|segment| segment.ident == "Daemonizable");
    if !is_daemonizable_impl {
        return Err(syn::Error::new_spanned(
            &item_impl.self_ty,
            "#[daemonizable::main] must be attached to an `impl Daemonizable for YourApp` block \
             (the trait path must end in `Daemonizable`)",
        ));
    }

    if !item_impl.generics.params.is_empty() {
        return Err(syn::Error::new_spanned(
            &item_impl.generics,
            "#[daemonizable::main] does not support generic impls: `daemonizable::run` needs \
             one concrete application type to dispatch on",
        ));
    }

    let self_ty = &item_impl.self_ty;
    Ok(quote! {
        #item_impl

        fn main() -> ::std::process::ExitCode {
            #crate_path::run::<#self_ty>()
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use quote::quote as q;

    // Tested directly on token streams, so there's no diagnostic-rendering drift
    // risk. The happy paths are additionally compiled for real by the trybuild
    // pass cases in daemonizable-e2e-tests/tests/macro_ui/.
    #[test]
    fn parse_crate_path_accepts_default_and_rename_and_rejects_junk() {
        // Empty → the absolute default path.
        let default = parse_crate_path(q!()).unwrap();
        assert_eq!(q!(#default).to_string(), q!(::daemonizable).to_string());

        // crate = "dz" → that path.
        let renamed = parse_crate_path(q!(crate = "dz")).unwrap();
        assert_eq!(q!(#renamed).to_string(), q!(dz).to_string());

        // A multi-segment path works too (a facade re-export).
        let nested = parse_crate_path(q!(crate = "facade::daemonizable")).unwrap();
        assert_eq!(
            q!(#nested).to_string(),
            q!(facade::daemonizable).to_string()
        );

        // Everything else is rejected: wrong key, non-string value, bare
        // tokens, and a non-path string.
        assert!(parse_crate_path(q!(krate = "dz")).is_err());
        assert!(parse_crate_path(q!(crate = 42)).is_err());
        assert!(parse_crate_path(q!(some junk)).is_err());
        assert!(parse_crate_path(q!(crate = "not a path")).is_err());
    }
}

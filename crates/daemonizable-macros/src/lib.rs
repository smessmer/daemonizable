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
/// not in scope here. The same example *is* compiled as a doctest in the
/// `daemonizable` crate root, and the macro's real expansion is covered by the
/// trybuild snapshots in `daemonizable-e2e-tests/tests/macro_ui/`.)
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
// TODO The Requirements list above presents itself as complete but omits one
//   limitation: the generated main hard-codes `::daemonizable::run`, so the
//   dependency must be named exactly `daemonizable` in Cargo.toml. A user
//   who renames it (`dz = { package = "daemonizable", ... }`) can invoke the
//   attribute as `#[dz::main]`, but the generated body fails with E0433
//   "unresolved crate or module `daemonizable`" anchored at the attribute
//   invocation, with nothing in the docs explaining why. Fix: add a
//   Requirements bullet documenting the naming requirement; optionally
//   support renames the way tokio/serde do, via an attribute argument
//   (`#[daemonizable::main(crate = "dz")]`) that substitutes the crate path
//   in the emitted main.
#[proc_macro_attribute]
pub fn main(attr: TokenStream, item: TokenStream) -> TokenStream {
    let item = proc_macro2::TokenStream::from(item);
    match expand(attr.into(), item.clone()) {
        Ok(expanded) => expanded.into(),
        Err(err) => {
            // Re-emit the original item alongside the error: the impl (or
            // whatever the attribute was attached to) stays alive, so the
            // caller sees our diagnostic instead of a cascade of unresolved
            // names.
            let err = err.to_compile_error();
            quote!( #item #err ).into()
        }
    }
}

fn expand(
    attr: proc_macro2::TokenStream,
    item: proc_macro2::TokenStream,
) -> syn::Result<proc_macro2::TokenStream> {
    if !attr.is_empty() {
        return Err(syn::Error::new(
            attr.span(),
            "#[daemonizable::main] takes no arguments",
        ));
    }

    let item_impl: syn::ItemImpl = syn::parse2(item.clone()).map_err(|_| {
        syn::Error::new(
            item.span(),
            "#[daemonizable::main] must be attached to an `impl Daemonizable for YourApp` block",
        )
    })?;

    let is_daemonizable_impl = item_impl
        .trait_
        .as_ref()
        .and_then(|(_, path, _)| path.segments.last())
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
            ::daemonizable::run::<#self_ty>()
        }
    })
}

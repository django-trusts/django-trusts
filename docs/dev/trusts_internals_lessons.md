# django-trusts internals: lessons from the 2026-10 refactor

> Historical development record. Last source update: 2026-10-19. Changes in this file have not been reviewed by a human for current accuracy.

Part 1 says what to do. Part 2 says how a module reads. Part 3 explains why,
because these rules came out of a refactor that ran for days and they are easy
to break again without the reasons.

## Part 1: What to do

### The shape

- **Recorder**: what `Backend().get_registry()` returns. One per backend
  class. It holds a single log of raw registration rows plus a `frozen`
  flag. It validates each row with the factory's stateless check functions
  and builds nothing. To applications, the recorder is the registry.
- **Compile step** (`trusts/compile/`): the single place where recorder rows
  become a built `Registry`. It runs exactly once, from `ready()`, for every
  configured backend, and fixes each catalog's family peers in that same
  sweep.
- **Catalog** (`trusts/compile/catalogs.py`): the one object a backend holds
  to answer questions. It is a front over the built `Registry`, not a holder
  and not a builder. It receives everything through its constructor.
- **Backend**: answers through `self.get_catalog()` and the Catalog's public
  methods. `get_catalog()` returning `None` means no grants: `has_perm` is
  `False`, `with_perm` has no users. A backend never raises or compiles
  because a catalog is missing.
- **`TrustsImplementationConfig`**: exists only to receive Django's
  `ready()`, so Trusts knows when to freeze, build, and check the lockfile.
  No attributes, no ownership, no lookups.

### Hard rules

1. **Top-level imports only.** If a cycle appears, stop and report the exact
   import chain. Never fix it with a function-level or lazy import.
2. **Pass it down through the constructor.** Whatever a lower-layer object
   needs (class, path, family, compiler, built registry, peers, user model)
   arrives in its constructor at build time. Nothing is looked up,
   re-derived, or probed at call time. `plan/`, `compile/`, query, and
   decorators never call `get_user_model()` or read settings.
3. **Cross modules only through public surfaces.** A module may construct
   another module's objects and call their public methods, passing itself or
   a data object with a known shape. It never reaches into another module's
   private names or attributes (`.registry`, `._factory`, `_helper`).
4. **No handles, owners, or carriers.** Do not invent an object whose job is
   to hold a path, class, or registry so something else can look it up later.
   If the information already exists (Django's `AUTHENTICATION_BACKENDS`,
   `type(self)`), use it once at build time.
5. **No probes on our own objects.** No `getattr`, `hasattr`, `callable`,
   `__self__`, or class-name string checks against objects this package
   defines. We know their types.
6. **Nothing after `ready()`.** Registration closes at `ready()`. No lazy
   build on first inquiry; a class compiled later is unsupported.
7. **No re-exports, shims, compat aliases, or "kept for downstream" names.**
   Nothing outside `docs/source/index.rst` is API. Unreleased things are
   removed outright: no deprecation, no migration note. Downstream breaks are
   named in the PR and fixed downstream.
8. **Refactors must shrink the code.** A simplification that nets more lines
   is the wrong simplification. Do not add holding, caching, or dual-store
   plumbing.
9. **Remove things in one pass.** Build the replacement in the place it
   belongs (Catalog, Registry, or factory), switch every caller, production
   and tests, at once, then delete the old piece. Prove it with greps that
   return zero. Never relocate a piece into whatever object is nearest.
10. **Tests follow the code.** "The tests are written that way" is never a
    reason to keep a shape. Tests written against an old shape get migrated,
    and tests that only assert an alias or export exists get deleted.
11. **Only application-facing modules sit at the top of `trusts/`.** The
    rest lives in a subfolder (`compile/`, `plan/`, `inspect/`). No grab-bag
    `commons` or `utils` modules: put each helper with the concept it serves.
12. **Keep user docs minimal.** A doc example shows only what an application
    must write. Any line added to `index.rst` is a promise the code must keep.

### Before you report

Grep for every name you claimed to remove, run the full suite, compare the
lockfile byte for byte, and check the line count went down. Report the
greps, and explain anything that resisted removal in production terms.

## Part 2: Code style

A module should read top to bottom the way a person would explain it.

1. Module docstring: what this module is, in a sentence or two. No notes
   about what it does not import.
2. Imports, all at the top: standard library, Django, then this package.
3. Module constants.
4. The entry point: the main class or function, the reason the file exists.
5. The major logic it calls, in the order it is called.
6. Private helpers at the bottom.

Inside a class, public methods come before private ones, and `__init__`
comes first. A reader should meet the thing they came for before its
plumbing.

Name things for what they are. A registry registers, a compiler compiles
and returns a result, a catalog answers. If a name needs a comment to say
what the object really does, rename it. "Sponsor" means only the person in
a delegation; do not reuse it for other relationships.

## Part 3: Why

### Why a stray doc line costs so much

`index.rst` is the API. When an example picked up `trusts_backend_paths` on
the app config, it looked harmless, almost like a settings comment. But it
was now a documented promise, so the code grew to honor it: ownership checks
at `ready()`, reverse lookups from class to path to config, a duplicate of
the backend list Django already keeps, then handle objects to carry the
result around. Every layer below began to depend on that machinery, and
removing it took days, because each piece seemed justified by the piece next
to it. In the end the answer was simple: there was never a reason for any of
it. The application that writes the backend also writes the config, so the
config naming its own backend said nothing new.

Keep examples to what an application must write. If you can't say why an
application needs a line, it shouldn't be in the docs.

### Why dependencies on internals are so hard to undo

An import cycle is visible, and you can often shuffle imports until it
disappears. A dependency on another module's internals is worse, because
nothing flags it. Once module A reads B's private attributes and B calls back
into A's helpers, every change has to keep both sides' private shapes alive.
Tests pick up those shapes too, so the internals start to look load-bearing.

That is how handles survived: each refactor moved the handle somewhere new
(into the backend, into the Recorder, into test helpers) because something
still read it, and that reader was there because the handle existed. Every
fix was one more whack in a game of whac-a-mole. What broke the loop was the
constructor rule: hand each object what it needs once, at build time, and
the carrier has nothing left to carry.

Lazy imports and lazy builds hide the same problem. They let a cycle or an
ordering bug go quiet instead of exposing it, so the dependency grows
further before anyone notices. That's why the rule is to surface the problem,
not work around it.

### Why "remove in one pass"

Removing something halfway leaves a compatibility layer, and that layer
becomes the next thing everything depends on. Since the lockfile already
sweeps every path, a structural change can always land at once and be
checked against it. A half-done removal is not progress; it is the next
handle.

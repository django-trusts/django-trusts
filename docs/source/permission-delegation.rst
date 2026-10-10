Permission Delegation: A Reference Model
========================================

Permission delegation is often described as giving another principal a
permission. That description hides the policy's most important fact.
Delegated authority exists only when a relationship and an authority source
are valid at the same time.

The relationship answers who may act, under which approval, scope, and state.
The sponsor answers whether the authority being exercised still exists.
Neither answer is sufficient by itself.

This article develops a framework-independent reference model for that
composition. It is not tied to a programming language, database, web
framework, identity provider, or product schema. It also records the questions,
candidate models, scorecards, and concrete counterexamples used to reach the
model.

Other models remain possible. A system that chooses one should be able to name
the additional requirement it serves, identify which reference properties it
does not provide, and accept or mitigate those consequences explicitly.

The reference rule is:

.. code:: text

   effective authority of the actor
   =
   the actor's independent authority
   OR
   (
       a matching delegation relationship
       AND
       the matching sponsor's live authority
   )

The relationship may narrow authority. It cannot manufacture authority the
sponsor does not have.

Terms and roles
---------------

``actor``
   The principal attempting the operation. An actor may be a person, service,
   agent, application installation, worker, session, or token holder.

``sponsor``
   The principal whose live authority supplies the ceiling. The sponsor is
   the bridge between the relationship and the system's ordinary authority
   policy. A sponsor need not be the requester, approver, or person who created
   the relationship.

``relationship``
   The evidence that this actor may act through this sponsor. It may also
   carry approval, resource selection, operation selection, tenant alignment,
   expiry, revocation, and other eligibility state.

``resource``
   The object or bounded set on which the actor wants to operate.

``operation``
   The action being requested on that resource.

These are policy roles, not required schema names. One record may expose all
of them, or an application may join several records to establish one
relationship.

A delegation relationship is not an ordinary grant
---------------------------------------------------

An ordinary grant states a complete proposition:

.. code:: text

   Alice may modify repository R.

A delegation relationship states an incomplete proposition:

.. code:: text

   Bot B may modify repository R through relationship D
   if sponsor Alice may currently modify repository R.

Relationship D may name an operation, but that operation is offered scope,
not self-sufficient authority. It becomes grant-producing only when the
sponsor side completes it.

Treating D as an ordinary grant removes the bridge. The actor remains
authorized when the sponsor loses authority because the relationship row is
now sufficient by itself. That is a copied grant with a different revocation
model, not live delegation.

The relational rule
-------------------

Let:

-  :math:`O(u,r,p)` mean that principal :math:`u` has qualifying ordinary
   authority for operation :math:`p` on resource :math:`r`.

-  :math:`D(d,u,s,r,p)` mean that relationship :math:`d` binds actor
   :math:`u`, sponsor :math:`s`, resource :math:`r`, and operation :math:`p`,
   and that all relationship-owned predicates hold.

-  :math:`A(u,r,p)` mean that :math:`u` is effectively authorized.

The one-level reference rule is:

.. math::

   A(u,r,p) = O(u,r,p)
   \lor \exists d,s\;\bigl(D(d,u,s,r,p) \land O(s,r,p)\bigr)

None of the variables may be discarded.

-  The sponsor comes from the exact relationship that matched the actor.

-  Relationship and sponsor authority meet on the same resource.

-  They meet on the same operation.

-  Approval, selection, tenant, lifetime, and revocation predicates belong to
   that same relationship match.

-  Another relationship belonging to the actor cannot lend its sponsor,
   approval, or scope.

Ordinary authority is usually a union of paths:

.. math::

   O(u,r,p) = O_1(u,r,p) \lor O_2(u,r,p) \lor \dots \lor O_n(u,r,p)

For a repository, those paths might be ownership, team membership, direct
collaboration, a role, or a source added later. The reference model reuses
that live union rather than copying it into every delegation relationship.

How the inquiry was conducted
-----------------------------

The investigation began with behavior, not an API. The first issue asked:

   "Can the existing declarative authorization model express these
   requirements without application callbacks or copied grants?"

   -- `Initial problem statement, issue #265
      <https://github.com/django-trusts/django-trusts/issues/265>`__

It also asked how missing or ambiguous relationship facts should fail closed,
and what bounds would govern chains, cycles, and traversal.

The follow-up deliberately prohibited choosing syntax first. It defined Cases
A through K and required more than one approach to be scored:

   "Cells = pass / fail only at first pass: use ✅ or ❌. Use ⚠️ only when the
   approach can pass with an explicit extra constraint."

   -- `Requirements and original scorecard, issue #266
      <https://github.com/django-trusts/django-trusts/issues/266#issuecomment-6007836197>`__

Every red and warning then required a concrete explanation rather than a vague
"needs more work" label.

Grok performed the candidate comparison and the later concrete model traces
through bounded Cursor design jobs. Chat reviewed the assumptions and returned
new questions rather than allowing a plausible first answer to become the API.
The record therefore includes false starts, corrected hypotheses, scratch
models, executable cases, and the reason the recommendation changed.

The cases were:

``A`` relationship scope can refuse a resource the sponsor may still use.

``B`` loss of the sponsor's last live path revokes without rewriting rows.

``C`` any remaining qualifying sponsor path keeps authority alive.

``D`` two relationships cannot borrow scope or authority from each other.

``E`` requester, approver, and runtime sponsor may be different facts.

``F`` the model is role-neutral, including a rich principal hiring a worker.

``G`` independent actor authority remains an independent branch.

``H`` expiry, revocation, and relationship state apply at decision time.

``I`` the policy remains declarative, inspectable, and consistently enforced.

``J`` both families meet on the resource; no universal delegation table is
required.

``K`` chaining has an explicit bound and fails closed.

Candidate models
~~~~~~~~~~~~~~~~

The investigation compared eight candidates:

``Remap``
   Substitute the sponsor for the actor and run the ordinary authority check.

``Copy``
   Materialize the sponsor's current grants as actor grants.

``Single``
   Encode one sponsor authority path inside one relationship traversal.

``Cartesian``
   Reproduce one complete relationship traversal for every sponsor path.

``Uncorrelated``
   Test whether the actor has any relationship and whether any associated
   sponsor has authority, without binding both results to the same row.

``Correlated``
   Complete each matching relationship with the live ordinary union of the
   sponsor bound by that exact relationship.

``Listed``
   Use the correlated model, but consult an explicit list of authority paths.

``Two-phase``
   Query the relationship, then perform a separate sponsor authorization
   check in application code.

Condensed green/red scorecard
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The original scorecard split the requirements into 22 columns. This condensed
version preserves the security-distinguishing results. The full table and the
reason for every red and warning remain in `the investigation record
<https://github.com/django-trusts/django-trusts/issues/266#issuecomment-6007836197>`__.

``N`` narrowing; ``V`` live revocation; ``U`` complete sponsor authority
union; ``X`` exact relationship correlation; ``D`` independent direct
authority; ``E`` consistent enforcement surfaces; ``B`` bounded chaining;
``T`` decision-time null, expiry, and revocation predicates in the inspected
engine. The ``T`` warning was a shared implementation prerequisite, not a
semantic advantage for another model.

.. list-table:: Candidate scorecard
   :header-rows: 1
   :widths: 18 5 5 5 5 5 5 5 5 7 7 7

   * - Approach
     - N
     - V
     - U
     - X
     - D
     - E
     - B
     - T
     - ✅
     - ❌
     - ⚠️
   * - Remap
     - ❌
     - ✅
     - ✅
     - ❌
     - ❌
     - ✅
     - ❌
     - ❌
     - 3
     - 5
     - 0
   * - Copy
     - ❌
     - ❌
     - ❌
     - ❌
     - ❌
     - ✅
     - ✅
     - ❌
     - 2
     - 6
     - 0
   * - Single
     - ✅
     - ✅
     - ❌
     - ✅
     - ✅
     - ✅
     - ✅
     - ⚠️
     - 6
     - 1
     - 1
   * - Cartesian
     - ✅
     - ✅
     - ❌
     - ✅
     - ✅
     - ✅
     - ✅
     - ⚠️
     - 6
     - 1
     - 1
   * - Uncorrelated
     - ✅
     - ✅
     - ✅
     - ❌
     - ✅
     - ✅
     - ⚠️
     - ⚠️
     - 5
     - 1
     - 2
   * - Correlated
     - ✅
     - ✅
     - ✅
     - ✅
     - ✅
     - ✅
     - ✅
     - ⚠️
     - 7
     - 0
     - 1
   * - Listed
     - ✅
     - ✅
     - ❌
     - ✅
     - ✅
     - ✅
     - ✅
     - ⚠️
     - 6
     - 1
     - 1
   * - Two-phase
     - ✅
     - ✅
     - ✅
     - ✅
     - ✅
     - ❌
     - ⚠️
     - ❌
     - 5
     - 2
     - 1

The detailed table found that only Correlated and Two-phase had no red on the
critical A through D properties. Two-phase then failed the shared-enforcement
requirement: list filtering and policy inspection could bypass the application
helper. Correlated was the only candidate with no critical red.

Why the nearest alternatives miss
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

``Single`` and ``Cartesian`` can encode a particular paired policy, but they
do not reuse the sponsor's existing authority union. A new ordinary authority
path remains invisible until the delegation policy is edited.

``Listed`` uses real authority paths, but a path omitted from the list does not
keep delegation alive. A path added later is absent until the list is updated.

``Uncorrelated`` reuses the union, but can complete relationship 1 with the
authority of relationship 2.

``Two-phase`` can return the correct answer in one service while list, bulk,
reverse, or audit consumers enforce a different policy.

``Copy`` changes the meaning from live delegation to materialized authority
with synchronization and revocation latency.

The concrete model trace
~~~~~~~~~~~~~~~~~~~~~~~~

The scorecard selected a survivor, but the team did not choose an API from
algebra alone. A second investigation built concrete organization, ownership,
team, collaborator, repository, installation, approval, and selection models.
It compared:

.. code:: text

   Shape 1
   (authority path a AND delegation path sa)
   OR (authority path b AND delegation path sb)
   OR ...

   Shape 2
   each complete relationship
   AND the exact sponsor's full ordinary authority union

The investigation initially appeared to favor the paired traversal. That
conclusion was paused:

   "My earlier recommendation to implement P was premature: organization-
   removal behavior alone does not distinguish shape 1 from shape 2."

   -- `Revised design baton, GH issue #43
      <https://github.com/django-trusts/django-trusts-gh-permissions/issues/43#issuecomment-6048891599>`__

The key correction was to put continuing organization membership on the
relationship side. When the sponsor leaves the organization, the relationship
fails even if a direct collaborator grant survives. The surviving grant never
gets a chance to complete that relationship. This is eligibility, not
authority provenance.

The follow-up was instructed to search for a counterexample where all
relationship facts held, the sponsor was authorized for the same resource and
operation, but delegation should still deny solely because the wrong ordinary
path supplied that authority. It tested GitHub-style access, hired-person
tasks, agent delegation, marketplace relationships, break-glass access,
temporary grants, public links, and a sponsor whose access was itself
delegated.

The reported result was:

   "Shape 2 holds up for every concrete case we have."

   "No demonstrated requirement needs shape 1 path provenance."

   -- `Shape 2 stress test, GH issue #43
      <https://github.com/django-trusts/django-trusts-gh-permissions/issues/43#issuecomment-6048998724>`__

The scratch relationship runner reported 21 cases and no failed expectations.
It could compile and execute the relationship half, but the then-current engine
could not compile the correlated sponsor-union half. That limitation was
recorded rather than treated as a passing implementation test. The complete
correlated rule was subsequently implemented and independently exercised in
the repository example.

Concrete stress-test results
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. list-table:: Selected model trace
   :header-rows: 1
   :widths: 58 20 22

   * - Event
     - Expected
     - Correlated result
   * - Approval and sponsor eligibility remain; any qualifying ordinary path grants
     - allow
     - allow
   * - Organization removes sponsor; approval remains
     - deny
     - deny on relationship eligibility
   * - One ordinary path is lost; another still grants
     - allow
     - allow through live union
   * - Collaborator grant survives after organization removal
     - deny
     - deny before authority union
   * - Operation is absent from one path but granted by another
     - allow
     - allow through live union
   * - Approval belongs to another installation
     - deny
     - deny on exact correlation
   * - Repository is deselected or operation removed
     - deny
     - deny on relationship scope
   * - Same actor has two installations
     - no cross-borrowing
     - each branch binds its own sponsor
   * - Actor has an independent direct grant
     - direct grant remains
     - independent outer branch
   * - Sponsor's only authority is itself delegated
     - deny in one-level profile
     - excluded from ordinary sponsor union

The trace also exposed a separate condition-language gap: revocation, null
tests, expiry, and a decision-time clock must be expressible in the same
policy. That was not evidence for path pairing. It was an independent
implementation prerequisite.

Composition across the two families
-----------------------------------

Within one authority path, required joins and conditions are naturally ANDed.
Separate ordinary paths are normally ORed. Separate delegation relationships
are also ORed, but only after each relationship branch is complete:

.. code:: text

   ordinary(actor, resource, operation)
   OR (
       relationship_1(actor, sponsor_1, resource, operation)
       AND ordinary(sponsor_1, resource, operation)
   )
   OR (
       relationship_2(actor, sponsor_2, resource, operation)
       AND ordinary(sponsor_2, resource, operation)
   )

It is sometimes summarized as:

.. code:: text

   (relationships) AND (ordinary sponsor paths)

That summary is safe only if the sponsor expression remains correlated inside
each matching relationship. Computing the two unions independently permits
cross-relationship borrowing.

Relationship eligibility is not authority provenance
----------------------------------------------------

Consider an organization-approved agent. Alice selects an organization and
repositories, the organization approves the installation, and the agent acts
under Alice's live authority. The product requires access to end when Alice
leaves the organization, even if Alice retains a direct collaborator grant on
one repository.

The relationship side can require Alice's continued organization eligibility:

.. code:: text

   relationship side:
       installation is approved
       AND actor, sponsor, and organization match
       AND resource and operation were selected
       AND sponsor still belongs to the required organization role

   authority side:
       sponsor is ordinarily authorized for this resource and operation

When Alice leaves, the relationship side fails. Her collaborator grant never
completes that relationship. While she remains eligible, any qualifying
ordinary path may satisfy the live ceiling.

The diagnostic question is:

   After relationship identity, sponsor eligibility, approval, resource,
   operation, and state all match, must the result still depend on which
   authority path happened to authorize the sponsor?

If no, use the complete qualifying ordinary union. If yes, provenance is an
additional product requirement and should be represented explicitly.

Reference invariants
--------------------

Relationship narrowing
~~~~~~~~~~~~~~~~~~~~~~

The actor receives no more resources or operations than the relationship
selects. Sponsor authority is a ceiling, not the actor's resulting scope.

Live sponsor ceiling
~~~~~~~~~~~~~~~~~~~~

Loss of the sponsor's last qualifying path removes delegated access without
waiting for copied grants to be rewritten.

Exact relationship correlation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Actor, sponsor, approval, selected scope, operation, and state come from one
matching relationship. Separate relationships cannot contribute fragments to
one synthetic authorization.

Same resource and operation
~~~~~~~~~~~~~~~~~~~~~~~~~~~

Relationship scope on resource A cannot combine with sponsor authority on
resource B. A delegated read cannot be completed by an unrelated write.

Independent actor authority
~~~~~~~~~~~~~~~~~~~~~~~~~~~

The actor's own ordinary authority remains an independent OR branch. Adding
delegation must not force an independently authorized actor through a
relationship.

Explicit authority-source policy
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The system states which authority sources may sponsor delegation. In the
one-level reference profile, delegated authority is excluded from the sponsor
side. A direct but nondelegable source is excluded explicitly rather than
through accidental behavior.

Principal eligibility and shortcut isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Actor and sponsor eligibility are part of the composed policy. Administrator,
break-glass, public, share-link, and other shortcuts must be assigned
explicitly to the actor's direct branch, the sponsor side, both, or neither.

Evaluating a high-level actor shortcut as the sponsor can import rules that
were never intended to sponsor delegation. The sponsor side evaluates the
authority sources selected by the delegation policy.

Consistent enforcement surfaces
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Single-resource decisions, collection filtering, operation enumeration,
reverse principal lookup, bulk work, and policy explanation implement the
same rule. A helper used by one endpoint does not establish system-wide
delegation semantics.

Current relationship state
~~~~~~~~~~~~~~~~~~~~~~~~~~

Approval, selection, expiry, revocation, tenant alignment, and principal
eligibility are current predicates. A system may materialize derived state,
but must state its freshness and revocation guarantees.

Alternative models and intentional tradeoffs
---------------------------------------------

The reference model is not the only possible model. A red is not a claim that
another model is forbidden. It is a property the design must willingly give
up, bound, or restore with another mechanism.

Copied or materialized authority
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Choose copying when disconnected evaluation or very cheap reads matter more
than immediate sponsor revocation. Specify synchronization ownership, maximum
revocation delay, behavior during sync failure, and whether changes to either
relationship scope or sponsor authority invalidate the copy.

Sponsor impersonation
~~~~~~~~~~~~~~~~~~~~~

Choose impersonation to reuse an existing evaluator with little new machinery.
Accept that sponsor scope is over-granted unless the exact relationship is
intersected, and preserve the real actor for audit and rate limiting. Once the
intersection is exact, the design is approaching the correlated model.

Path-paired provenance
~~~~~~~~~~~~~~~~~~~~~~

Choose path pairing when the product genuinely cares how the sponsor obtained
authority. A break-glass source may never be delegable. A regulated operation
may require ownership. One delegation kind may accept team authority while
another may not.

If a rule applies to an authority source for every delegation, mark that
source delegable or nondelegable. If it depends jointly on delegation kind and
authority path, use an explicit pairing matrix.

That matrix couples delegation maintenance to ordinary-policy maintenance.
Every new authority path requires a decision for each relevant delegation
kind. Choose that cost for a demonstrated provenance requirement, not merely
because two paths happen to share a join.

Recursive delegation
~~~~~~~~~~~~~~~~~~~~

Replacing :math:`O(s,r,p)` with effective authority :math:`A(s,r,p)` allows a
sponsor to rely on delegated authority. This creates a graph, not a single
bridge. The design must define depth or termination, cycles, attenuation,
eligibility at every edge, downstream revocation, nondelegable sources, and
explanation of the complete chain.

One-level delegation is not a claim that deeper delegation is conceptually
wrong. It is a bounded profile that declines these semantics until they are
needed and defined.

Portable capabilities and signed tokens
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

Choose a capability when cross-system or offline verification matters. Its
advantage is its deliberate departure from a live sponsor lookup. State how
short expiry, introspection, revocation lists, key rotation, audience binding,
or proof-of-possession restore the required properties.

Separate service checks
~~~~~~~~~~~~~~~~~~~~~~~

Architectural boundaries may require one service to validate the relationship
and another to validate sponsor authority. Preserve relationship identity,
sponsor, resource, operation, and decision time across the boundary. Reproduce
the same rule for lists, bulk work, reverse lookup, and audit output.

Choosing the sponsor authority set
----------------------------------

"Sponsor authority" is incomplete until the qualifying source set is named:

1. Start with all live ordinary sources.

2. Exclude source families that are never delegable.

3. Add path pairing only when the same source is acceptable for one
   relationship kind and forbidden for another.

4. Include delegated authority only after recursive semantics are defined.

This progression preserves the common rule while allowing real requirements
to refine it.

Relationship representation
---------------------------

No universal delegation table is required. Applications may use an approved
app installation, agent connection, client engagement, support session,
marketplace transaction, or selected-scope token grant.

The representation must establish actor, sponsor, resource, operation, and
relationship predicates. Stable relationship identity may be separate from
selected scope:

.. code:: text

   Installation
       actor
       sponsor
       tenant

   Approval
       installation
       approver
       approval state

   Selected scope
       installation
       resource
       operation
       expiry and revocation state

Constraints and policy conditions prevent approval or scope from one
installation authorizing another.

Evaluation requirements
-----------------------

The evaluator may use relational queries, a graph engine, a policy engine,
capability validation, remote calls, or materialized state. The logical
obligations remain:

1. Evaluate the actor's independent authority.

2. Find each applicable delegation relationship.

3. Bind that relationship's actor, sponsor, resource, operation, and state.

4. Evaluate the selected sponsor authority sources for that correlated
   sponsor, resource, and operation.

5. AND each relationship with its own sponsor result.

6. OR only the completed branches.

Incompatible principal types, resource types, operation namespaces, or policy
domains are rejected, declared inapplicable, or bridged by an explicit
mapping. They are not silently compared as though they shared identity.

Time-dependent state uses a decision-time value consistent throughout one
evaluation. A relationship must not be active at one stage and expired at
another because separate checks used different clocks or snapshots.

Enforcement surfaces
--------------------

Single-resource decisions
~~~~~~~~~~~~~~~~~~~~~~~~~

The common "may actor U perform P on R?" decision evaluates independent
authority and every complete correlated delegation branch.

Collection filtering
~~~~~~~~~~~~~~~~~~~~

Apply the same rule before pagination and before returning protected fields.
Fetching everything and filtering later is easy to bypass.

Operation enumeration
~~~~~~~~~~~~~~~~~~~~~

List a delegated operation only when relationship and sponsor authority both
currently match.

Reverse principal inquiry
~~~~~~~~~~~~~~~~~~~~~~~~~

Asking which actors may perform an operation preserves each relationship's
own sponsor and state. The sponsor does not become a global actor substitute.

Bulk and asynchronous work
~~~~~~~~~~~~~~~~~~~~~~~~~~

Bulk jobs, queued work, and retries define whether authority is checked at
submission, execution, or both. A decision snapshot is a capability with a
freshness policy, even when the system does not call it one.

Explanation and audit
~~~~~~~~~~~~~~~~~~~~~

An explanation identifies the direct branch or the exact relationship,
sponsor, qualifying authority source, resource, operation, and relevant state.
"Allowed by delegation" is not enough for incident review.

Decision checklist
------------------

1. Which exact relationship binds actor and sponsor?

2. Which facts represent approval, selected scope, and current eligibility?

3. Can the relationship narrow below sponsor authority?

4. Does loss of the last qualifying sponsor path revoke immediately?

5. Do both sides meet on the same resource and operation?

6. Can two relationships be combined accidentally?

7. Does independent actor authority remain independent?

8. Which authority sources may sponsor delegation?

9. Does authority provenance matter, and for which concrete requirement?

10. Is delegation one level or recursive? What terminates a chain?

11. How do expiry, revocation, tenant changes, and principal inactivity affect
    a current decision?

12. Do point, list, enumeration, reverse, bulk, and audit surfaces agree?

13. What is the maximum revocation delay?

14. Which failures deny, which configurations are rejected, and which sources
    are merely inapplicable?

15. Can the system explain the exact relationship and sponsor authority that
    completed an allowed decision?

How to justify a departure
--------------------------

A design that departs from the reference model should record:

.. code:: text

   Requirement served:
       The concrete behavior the reference model does not provide.

   Chosen model:
       Copy, impersonation, path pairing, recursion, capability,
       separate checks, or another named design.

   Reference properties not provided:
       The accepted ❌ and ⚠️ items.

   Compensating controls:
       Revalidation, expiry, synchronization, bounded depth,
       cycle detection, audit, or another mechanism.

   Revocation and failure semantics:
       Maximum delay and behavior during partial failure.

   Enforcement coverage:
       Point, list, bulk, reverse, enumeration, and audit surfaces.

This turns "our delegation works differently" into a reviewable policy choice.

Conclusion
----------

Permission delegation is not permission copying and not identity
substitution. It is a conditional authority relationship.

The relationship family answers:

.. code:: text

   Who may act, through which relationship, on which resource,
   for which operation, under which approval and current state?

The sponsor authority family answers:

.. code:: text

   Does that relationship's sponsor currently hold qualifying authority
   for the same resource and operation?

Correlation joins those answers without flattening either family. The
relationship remains narrow. Sponsor authority remains live. Independent
authority remains independent.

Systems may choose another model. They should do so because a named
requirement demands it, with lost properties and compensating controls made
explicit.

Application note: django-trusts
-------------------------------

django-trusts applies the reference model as a bounded one-level profile:

-  ordinary registrations remain grants;

-  delegated registrations bind the actor with ``delegate=`` and the live
   authority source with ``sponsor=``;

-  the requested permission comes from the inquiry and may be narrowed by
   relationship conditions;

-  each relationship is completed by the sponsor's live union of applicable
   ordinary registrations on the same content and permission;

-  multiple delegation models remain separate correlated branches;

-  delegated registrations are excluded from the sponsor-side union; and

-  object decisions, permitted-object filtering, permission enumeration,
   reverse permitted-user inquiry, and policy output share the composed rule.

The framework's exact API, validation, path grammar, temporary ``along=``
boundary, and test obligations belong to the `delegation registration
contract <https://github.com/django-trusts/django-trusts/blob/dev/docs/dev/delegation-registration.md>`__.
Those choices apply the reference model; they do not define it.

Research trail
--------------

-  `Initial questions and required behavior
   <https://github.com/django-trusts/django-trusts/issues/265>`__

-  `Cases A through K and full requirements scorecard
   <https://github.com/django-trusts/django-trusts/issues/266#issuecomment-6007836197>`__

-  `Concrete model trace and corrected alternatives
   <https://github.com/django-trusts/django-trusts-gh-permissions/issues/43>`__

-  `Final shape 2 stress test
   <https://github.com/django-trusts/django-trusts-gh-permissions/issues/43#issuecomment-6048998724>`__

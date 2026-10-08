Considerations in Permission Delegation
=======================================

Permission delegation is often implemented as if it were permission copying. A user authorizes an application, agent, worker, or connected account; the system creates rows that resemble ordinary grants; and later checks ask whether those rows still exist. That design is simple, but it loses the fact that delegated authority depends on two independent families of evidence.

The first family belongs to the relationship: which actor may act, for which content, for which operations, under which approval, selection, lifetime, and organizational boundary. The second family belongs to the sponsor: whether that sponsor is presently permitted to perform the same operation on the same content through the system’s ordinary authorization policy.

A delegated decision therefore has the form:

.. code:: text

   ordinary authority of the actor
   OR
   (
       a matching delegation relationship
       AND
       the sponsor's live ordinary authority
   )

This structure preserves narrowing and revocation at the same time. The relationship may be narrower than the sponsor’s authority, and the sponsor’s loss of authority immediately removes the delegated result. The difficult part is not the Boolean AND itself. The difficult part is preserving the exact relationship, sponsor, content, and operation while the sponsor’s ordinary authority remains an OR-union of independently registered paths.

Delegation is a conditional authority relationship
--------------------------------------------------

An ordinary permission states a direct proposition:

.. code:: text

   Alice may modify repository R.

A delegation states a conditional proposition:

.. code:: text

   Bot B may modify repository R through relationship D
   only while sponsor Alice may modify repository R.

The stored delegation is not an ordinary grant. It supplies the acting principal, selected content, delegated operations, approval, and other relationship state. It becomes grant-producing only when the sponsor’s live authority completes it.

This distinction matters even when both relationships terminate at the same permission object. A database column may still point at ``modify_repository``, but its policy role differs. In an ordinary grant, that terminal permission is sufficient when the path matches. In a delegation, the terminal operation describes the scope offered by the relationship; it remains insufficient without the sponsor bridge.

Treating both rows as ordinary grants creates an authorization hole. The delegation row enters the usual OR-union, so matching the actor, content, and operation authorizes the request even when the sponsor has no authority. A correct compiler must know that a delegated relationship is non-ordinary and must keep it out of both the actor’s direct branch and the sponsor’s ordinary union.

A relational formulation
------------------------

Let:

-  :math:`O(u,c,p)` mean that principal :math:`u` has ordinary permission :math:`p` on content :math:`c`.

-  :math:`D(r,u,s,c,p)` mean that relationship row :math:`r` delegates operation :math:`p` on content :math:`c` to acting principal :math:`u`, with sponsor :math:`s`, and that the relationship's own predicates hold.

-  :math:`P(u,c,p)` mean that :math:`u` is permitted to perform :math:`p` on :math:`c`.

The delegated policy is:

.. math::

   P(u,c,p) = O(u,c,p) \lor \exists r,s\; \bigl(D(r,u,s,c,p) \land O(s,c,p)\bigr)

The variables :math:`r`, :math:`s`, :math:`c`, and :math:`p` are not incidental. They are the correlation boundary.

-  The sponsor must come from the exact relationship row that matched the actor.

-  Both sides must meet on the same content.

-  Both sides must meet on the same operation.

-  Conditions on the relationship must be evaluated inside the same existential match.

-  Another relationship belonging to the same actor cannot contribute its sponsor, approval, or scope.

The ordinary predicate :math:`O` is itself generally a union:

.. math::

   O(u,c,p) = O_1(u,c,p) \lor O_2(u,c,p) \lor \dots \lor O_n(u,c,p)

An application may permit a repository operation through ownership, team membership, direct collaboration, a role, or a future path added after the delegation feature ships. Delegation should normally reuse that live union rather than copy each path into a second policy.

OR within families and AND across families
------------------------------------------

Most relationship authorization systems already have two useful rules:

1. Hops within one registered path are ANDed. Every required join and condition must hold.

2. Separate grant paths are ORed. Any applicable ordinary path may authorize.

Delegation introduces a third composition rule:

.. code:: text

   OR within the delegation family
   AND
   OR within the sponsor's ordinary authority family

For ordinary paths :math:`a`, :math:`b`, and :math:`c`, and delegation relationships :math:`s_1` and :math:`s_2`, the common rule is:

.. code:: text

   (a | b | c) AND (s1 | s2)

This expression is safe only when correlation is preserved. A more exact reading is:

.. code:: text

   EXISTS matching relationship S:
       S matches actor + content + operation
       AND ordinary(S.sponsor, same content, same operation)

The compiler cannot evaluate the two unions independently and combine their truth values later. That would allow a relationship from one installation to borrow authority from another sponsor or organization.

A different policy is possible:

.. code:: text

   (a AND sa) OR (b AND sb) OR (c AND sc)

That rule makes the provenance of the sponsor’s permission part of the delegation. It is more specific and substantially harder to maintain because each delegated path must reproduce or name its permitted authority paths. The general model should require this pairing only when the product actually cares how the sponsor obtained permission.

Relationship eligibility is not permission provenance
-----------------------------------------------------

Many apparent provenance requirements are actually relationship eligibility requirements.

Consider an organization-approved bot relationship. Thomas selects an organization and repositories, the organization approves the relationship, and the bot acts under Thomas’s live authority. The product requires the bot to lose organization access when Thomas is removed from the organization, even if Thomas retains a direct collaborator grant on one repository.

At first glance, that appears to require pairing the organization delegation only with the organization-owner permission path. It does not. The relationship side can require Thomas’s continuing organization relationship:

.. code:: text

   left side:
       this installation was approved
       AND this bot, sponsor, and organization match
       AND this repository and operation were selected
       AND the sponsor still owns or belongs to this organization

   right side:
       the sponsor is ordinarily permitted for this repository and operation

After Thomas is removed, the left side fails. His surviving collaborator permission never gets a chance to complete the relationship. While Thomas remains eligible, any ordinary path that permits the same operation may satisfy the live ceiling.

The distinction can be stated as a diagnostic question:

   If the relationship, sponsor eligibility, approval, content, operation, and state all match, must the result still depend on which ordinary grant path happened to authorize the sponsor?

If the answer is no, the complete ordinary union is the correct authority side. If the answer is yes, permission provenance is part of the product policy and requires an additional mechanism.

Invariants of a delegated permission system
-------------------------------------------

A delegated permission system should preserve the following invariants.

Relationship narrowing
~~~~~~~~~~~~~~~~~~~~~~

The actor receives no more content or operations than the relationship selects. A sponsor who can reach every repository in an organization may still delegate only one repository and one operation.

Live authority ceiling
~~~~~~~~~~~~~~~~~~~~~~

The actor loses delegated access when the sponsor loses the last applicable ordinary path. The system does not depend on a cleanup job rewriting copied grants.

Principal state and shortcut isolation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The acting principal must pass the same active-principal check before either the direct or delegated branch can authorize. A sponsor contributes authority only while that sponsor is also active. django-trusts does not treat ``is_superuser`` as implicit authority in either branch. A superuser is an ordinary principal unless the application registers a trust path that grants authority. Django admin may continue to apply its own superuser behavior through its authentication backend; that application-level choice does not enter the django-trusts policy or the sponsor-side ordinary union.

Exact relationship correlation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The sponsor, approval, content selection, operation selection, and state must come from one matching relationship. Two installations owned by the same actor cannot borrow facts from each other.

Same content and operation
~~~~~~~~~~~~~~~~~~~~~~~~~~

A relationship selecting repository A cannot combine with sponsor authority on repository B. A delegated read cannot combine with sponsor write or vice versa merely because both concern the same object.

Independent ordinary authority
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

The actor’s own ordinary grants remain a separate OR branch. Adding delegation must not force an independently permitted account through a delegation relationship.

Bounded delegation
~~~~~~~~~~~~~~~~~~

A sponsor whose only access is delegated is not an ordinary authority source in a one-hop design. Delegated records must be excluded from the inner ordinary union. Longer chains require an explicit policy, depth bound, and cycle behavior.

Declarative equivalence
~~~~~~~~~~~~~~~~~~~~~~~

Point checks, permitted querysets, permission enumeration, reverse principal inquiry, and emitted policy SQL must compile the same logical rule. A helper around one view or MCP endpoint does not establish an authorization policy.

Common designs and their failure modes
--------------------------------------

Copying grants
~~~~~~~~~~~~~~

A system may copy the sponsor’s current grants onto the actor when the relationship is approved. This loses live revocation. When the sponsor leaves a team or loses ownership, the copied rows remain until a separate process finds and rewrites them. Relationship scope and authority provenance also collapse into one pool of actor-level grants.

Substituting the sponsor for the actor
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A system may rerun the ordinary check as the sponsor. This preserves live authority but loses narrowing. The actor inherits everything the sponsor can reach unless a second relationship predicate is applied in the same authorization plan.

Adding one sponsor hop to one path
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A single longer join can express one paired policy. It cannot reuse an ordinary authority union whose alternatives start from different models or relationship handles. A new ordinary path remains invisible until the paired policy is edited.

Combining uncorrelated families
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A system may check whether the actor has any relationship and whether any associated sponsor has authority. This admits cross-relationship borrowing. Approval and scope from one installation can combine with authority belonging only to another.

Running two application checks
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A service may query the relationship and then call an ordinary permission check for the sponsor. The result may be correct for that service, but queryset filtering, reverse inquiry, permission enumeration, and policy export still see a different policy. Other callers can skip the helper.

Reproducing authority paths in relationship conditions
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An application can sometimes join concrete ownership, team, or collaborator rows from the delegation root and reproduce their predicates in a registration condition. This is useful as a bounded proof. It duplicates policy, fails to include paths added later, and makes the application schema carry forward links to authority records solely to make one traversal compile.

A public registration model
---------------------------

A public API should make the two roles visible. A tentative shape is:

.. code:: python

   backend.register(
       trust=Delegation,
       user=lambda d: d.acting_user,
       delegation=lambda d: d.operation,
       content=lambda d: d.repository,
       sponsor=lambda d: d.installation.sponsor,
       condition=lambda d: (
           approval_matches(d)
           & sponsor_is_eligible(d)
           & relationship_is_active(d)
       ),
   )

The names are less important than the contract:

-  ``user`` binds the acting principal being checked.

-  ``delegation`` binds the operation offered by the relationship.

-  ``content`` binds the protected object.

-  ``sponsor`` binds the principal whose ordinary authority supplies the live ceiling.

-  ``condition`` narrows the relationship through approval, organization alignment, selected scope, lifetime, revocation, and application-specific eligibility.

A delegated registration must be distinguishable from ordinary ``permission=`` and ``group=`` registrations. It cannot participate as an ordinary grant, and ordinary registration cannot silently acquire delegation semantics because a sponsor-like field happens to be present.

The operation terminal may use the same underlying permission model and path shapes as an ordinary registration. The separate argument records its policy role, not necessarily a different database type.

Compiler requirements
---------------------

The compiler needs an aggregate view of ordinary authority. Compiling delegation entirely inside one relationship plan is insufficient when ordinary owner, team, and collaborator paths live under different configured handles.

For each candidate content and operation, the compiler must:

1. Compile the actor’s direct ordinary union.

2. Find matching delegated relationship records.

3. Apply the relationship’s user, content, operation, sponsor, and condition bindings.

4. Compile every applicable ordinary authority handle with its user binding replaced by the correlated sponsor expression from that exact row.

5. OR those ordinary predicates while retaining the surrounding relationship EXISTS.

6. Exclude all delegated records from the inner union.

7. OR the completed delegated result with the actor’s direct ordinary result.

Conceptually:

.. code:: sql

   ordinary_for_actor
   OR EXISTS (
       SELECT 1
       FROM relationship AS d
       WHERE d.actor = :actor
         AND d.content = candidate_content
         AND d.operation = :operation
         AND relationship_condition(d)
         AND (
             ordinary_handle_a(d.sponsor, candidate_content, :operation)
             OR ordinary_handle_b(d.sponsor, candidate_content, :operation)
             OR ordinary_handle_c(d.sponsor, candidate_content, :operation)
         )
   )

The expression must fail closed when content models, permission models, backend identities, or sponsor principal types are incompatible. An absent or inapplicable ordinary handle contributes no authority. A malformed applicable configuration should fail loudly during registration or planning rather than disappear as a silent denial.

Conditions, time, and revocation
--------------------------------

Relationship state belongs inside the authorization predicate. Common fields include:

-  approval state;

-  selected repositories or objects;

-  allowed operations or tools;

-  organization or tenant alignment;

-  ``revoked_at``;

-  ``expires_at``;

-  activation or adoption timestamps.

A condition language that supports only equality between model paths and permission membership cannot express two common rules:

.. code:: text

   revoked_at IS NULL
   expires_at > database_now

Evaluating these only during relationship creation or cleanup leaves stale rows effective. Evaluating them in Python after authorization causes point checks and queryset filtering to disagree.

The condition system therefore needs null predicates and ordered comparisons against a database-side clock fixed for the query. Registration must store a symbolic expression, not the result of calling a clock during application startup. The same compiled predicate must appear in point checks, querysets, reverse inquiries, and policy SQL.

Inquiry-time named conditions require separate care. Their principal references ordinarily mean the acting principal. A compiler should not rebound them independently to the sponsor inside every authority handle. They should apply once at the level defined by the inquiry contract.

Permission provenance and nondelegable authority
------------------------------------------------

The base model intentionally forgets which ordinary path succeeded. It asks whether the sponsor is permitted for the same content and operation.

Some products may later need a stronger rule:

-  break-glass access may never be delegated;

-  a temporary emergency grant may be usable only by its holder;

-  public or share-link access may not establish sponsorship;

-  delegation kind X may use only an ownership path while kind Y may use only a team path.

The first three examples can often be expressed by marking an ordinary registration family as ineligible for the sponsor-side union. The sponsor may still use that path directly, but the correlated inner compiler skips it. This adds a property of an authority source without reproducing all allowed pairs.

The fourth example is genuinely path-paired. The same ordinary path is acceptable for one delegation kind and forbidden for another. It requires named authority families, paired registrations, or another explicit provenance policy.

Provenance should enter the base API only after a real product requirement establishes it. Adding path identity too early replaces a stable Boolean rule with a matrix of pairings that applications must keep synchronized with their ordinary policy.

Authorization surfaces
----------------------

Delegation is incomplete if it works only for ``has_perm()``.

Point checks
~~~~~~~~~~~~

A point check evaluates direct ordinary authority and the correlated delegation branch for one actor, content object, and operation.

Permitted querysets
~~~~~~~~~~~~~~~~~~~

A queryset must embed the same correlated EXISTS against each candidate row. It cannot retrieve all content and filter in Python. Authorization must occur before pagination.

Permission enumeration
~~~~~~~~~~~~~~~~~~~~~~

Enumerating an actor’s permissions on content must include an operation only when both the relationship and sponsor authority match. The enumeration cannot treat stored delegated operations as grants by themselves.

Reverse principal inquiry
~~~~~~~~~~~~~~~~~~~~~~~~~

Asking which users are permitted on one content and operation must seed the same relationship predicate in reverse. The sponsor remains a correlated field on each relationship; it is not a globally substituted inquiry user.

Policy SQL and lock files
~~~~~~~~~~~~~~~~~~~~~~~~~

Inspectable policy output should show the relationship EXISTS and sponsor ordinary union. Operators need to see that both families participate and that delegated records are excluded from the inner union.

These surfaces should share one plan node or one aggregate compiler. Independent implementations will drift precisely at the boundaries that make delegation difficult.

Application-owned relationship models
-------------------------------------

Core authorization should not require one universal ``Delegation`` table. Applications already have different relationship models:

-  an app installation approved by an organization;

-  an agent connection created by a human;

-  a client engagement assigned to a contractor;

-  a marketplace transaction with a worker and customer;

-  a support session approved for selected resources;

-  a personal token with selected repositories and operations.

The model needs only to expose paths for the acting principal, sponsor, content, operation, and relationship predicates.

A typical application may separate stable relationship identity from selected scope:

.. code:: text

   Installation
       acting principal
       sponsor
       organization or tenant

   Approval
       installation
       approver and approval state

   Delegated scope
       installation
       selected content
       delegated operation
       expiry and revocation state

Database constraints and authorization conditions should bind these rows to the same relationship. An approval for one bot or installation cannot authorize another. A sponsor cannot be swapped while reusing an approval for the previous sponsor unless the product explicitly permits reassignment.

Worked cases
------------

Organization-approved agent
~~~~~~~~~~~~~~~~~~~~~~~~~~~

An owner connects an agent, selects repositories and operations, and obtains organization approval. The relationship requires the sponsor to remain an eligible owner. The sponsor’s live repository authority may come from ownership, a team, or direct collaboration. Removal from ownership fails the relationship side even if a collaborator grant survives.

Hired human under a rich principal
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A client hires a worker for one task. The task row selects content and operations; the client is the sponsor. The worker receives only the intersection of the task scope and the client’s live authority. The model is role-neutral: Core does not need to know which principal is human or automated.

Multiple organizations
~~~~~~~~~~~~~~~~~~~~~~

One actor has two installations with different sponsors and approvals. Each relationship row binds its own sponsor, organization, content, and state. Authority from one sponsor cannot complete the other installation.

Independent and delegated access together
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

An actor has a direct collaborator grant on repository A and a delegated relationship for repository B. Direct access remains an ordinary branch. Revoking the delegation affects B without changing A.

Sponsor whose access is delegated
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

A contractor acts through a client-sponsored relationship and attempts to sponsor another agent. Under a one-hop policy, the contractor has no qualifying ordinary authority from that relationship. The second delegation fails unless the contractor also has an independent ordinary grant.

Design checklist
----------------

Before adopting a delegation design, answer these questions:

1.  Which row binds the acting principal?

2.  Which exact row binds the sponsor?

3.  Which facts represent approval, selection, and current relationship eligibility?

4.  Can the relationship deny content or operations the sponsor may still access?

5.  Does loss of the sponsor’s last ordinary path revoke access immediately?

6.  Do both sides meet on the same content and operation?

7.  Can two relationships belonging to one actor borrow facts from each other?

8.  Does the actor’s independent ordinary authority remain a separate branch?

9.  Are delegated records excluded from the sponsor-side union?

10. What is the chain depth, and how do cycles fail?

11. Do point checks, querysets, enumeration, reverse inquiry, and policy SQL share the same plan?

12. Can revocation and expiry be expressed inside that plan?

13. Does the product truly care which ordinary path authorized the sponsor?

14. If some ordinary paths are nondelegable, can the inner union exclude them explicitly?

15. What configuration errors fail during registration, and which inapplicable paths contribute no authority?

Open design questions
---------------------

The semantic model does not settle every public API detail.

-  Whether ``delegation=`` is the clearest name for the operation terminal.

-  Whether delegated group bundles need their own argument or share one terminal contract.

-  How sponsor principal types are validated in systems with more than one principal model.

-  How an aggregate plan represents ordinary handles from multiple configured backends.

-  Which named conditions refer to the actor, sponsor, or content, and whether sponsor-relative inquiry conditions are ever needed.

-  How reverse inquiry interacts with recursive reachability features.

-  Whether ordinary registrations need a future ``delegable`` property.

-  Which database clock expression provides stable query-time expiry semantics across supported databases.

-  How policy SQL identifies the inner ordinary union without obscuring the relationship correlation.

These questions should be answered against executable cases. The core equation is useful precisely because it lets API and compiler proposals be judged without confusing syntax with semantics.

Conclusion
----------

Permission delegation is an intersection, not a copied grant and not a change of identity.

The relationship family answers:

.. code:: text

   Who may act, under which relationship, on which content,
   for which operation, under which approval and state?

The ordinary authority family answers:

.. code:: text

   Is this relationship's sponsor presently permitted
   for that same content and operation?

Correlation joins those answers without flattening either family. The relationship remains narrow. The sponsor’s authority remains live. Direct authority remains independent. Applications keep their own schemas, while the authorization engine supplies the shared algebra.

That algebra is small:

.. math::

   O(u,c,p)
   \lor \exists r,s\;
   \bigl(D(r,u,s,c,p) \land O(s,c,p)\bigr)

Most of the engineering follows from refusing to lose the variables inside it.

Project sources
---------------

-  `Core issue 265: Delegated access problem statement <https://github.com/django-trusts/django-trusts/issues/265>`__

-  `Core issue 266: Detailed requirements and correlated design <https://github.com/django-trusts/django-trusts/issues/266>`__

-  `GH permissions issue 43: Concrete model and provenance stress test <https://github.com/django-trusts/django-trusts-gh-permissions/issues/43>`__

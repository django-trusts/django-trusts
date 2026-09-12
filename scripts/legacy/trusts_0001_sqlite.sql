-- Representative django-trusts 0.10.3 / pre-modernization SQLite schema.
-- Matches trusts.0001_initial field layout at legacy-pre-modernization.
-- Django 1.8 CASCADE was implicit and Python-level; this SQL has no
-- ON DELETE CASCADE clauses, same as the historical table.

CREATE TABLE "trusts_trust" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "title" varchar(40) NOT NULL,
    "settlor_id" integer NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED,
    "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX "trusts_trust_settlor_id_title_6e2b0c8a_uniq"
    ON "trusts_trust" ("settlor_id", "title");

CREATE TABLE "trusts_trust_groups" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED,
    "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX "trusts_trust_groups_trust_id_group_id_uniq"
    ON "trusts_trust_groups" ("trust_id", "group_id");

CREATE TABLE "trusts_trustuserpermission" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "entity_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED,
    "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED,
    "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX "trusts_trustuserpermission_trust_id_entity_id_permission_id_uniq"
    ON "trusts_trustuserpermission" ("trust_id", "entity_id", "permission_id");

CREATE TABLE "trusts_role" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "name" varchar(80) NOT NULL UNIQUE
);

CREATE TABLE "trusts_role_groups" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "role_id" integer NOT NULL REFERENCES "trusts_role" ("id") DEFERRABLE INITIALLY DEFERRED,
    "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX "trusts_role_groups_role_id_group_id_uniq"
    ON "trusts_role_groups" ("role_id", "group_id");

CREATE TABLE "trusts_rolepermission" (
    "id" integer NOT NULL PRIMARY KEY AUTOINCREMENT,
    "managed" bool NOT NULL,
    "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED,
    "role_id" integer NOT NULL REFERENCES "trusts_role" ("id") DEFERRABLE INITIALLY DEFERRED
);
CREATE UNIQUE INDEX "trusts_rolepermission_role_id_permission_id_uniq"
    ON "trusts_rolepermission" ("role_id", "permission_id");

BEGIN;
--
-- Custom state/database change combination
--
-- (no-op)
--
-- Create model TrustGroupPermission
--
CREATE TABLE "trusts_trustgrouppermission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED, "trustgroup_id" integer NOT NULL REFERENCES "trusts_trust_groups" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Alter unique_together for trustgrouppermission (1 constraint(s))
--
CREATE UNIQUE INDEX "trusts_trustgrouppermission_trustgroup_id_permission_id_f6d3ca26_uniq" ON "trusts_trustgrouppermission" ("trustgroup_id", "permission_id");
--
-- Add field permissions to trustgroup
--
CREATE TABLE "new__trusts_trust_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED, "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED);
INSERT INTO "new__trusts_trust_groups" ("id", "group_id", "trust_id") SELECT "id", "group_id", "trust_id" FROM "trusts_trust_groups";
DROP TABLE "trusts_trust_groups";
ALTER TABLE "new__trusts_trust_groups" RENAME TO "trusts_trust_groups";
CREATE INDEX "trusts_trustgrouppermission_permission_id_77388644" ON "trusts_trustgrouppermission" ("permission_id");
CREATE INDEX "trusts_trustgrouppermission_trustgroup_id_2b5e9a33" ON "trusts_trustgrouppermission" ("trustgroup_id");
CREATE UNIQUE INDEX "trusts_trust_groups_trust_id_group_id_1f72e20c_uniq" ON "trusts_trust_groups" ("trust_id", "group_id");
CREATE INDEX "trusts_trust_groups_group_id_2e2f4c3a" ON "trusts_trust_groups" ("group_id");
CREATE INDEX "trusts_trust_groups_trust_id_36f34742" ON "trusts_trust_groups" ("trust_id");
COMMIT;

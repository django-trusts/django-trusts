BEGIN;
--
-- Create model Trust
--
CREATE TABLE "trusts_trust" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "title" varchar(40) NOT NULL, "settlor_id" integer NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED, "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED);
CREATE TABLE "trusts_trust_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Create model TrustUserPermission
--
CREATE TABLE "trusts_trustuserpermission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "entity_id" integer NOT NULL REFERENCES "auth_user" ("id") DEFERRABLE INITIALLY DEFERRED, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED, "trust_id" integer NOT NULL REFERENCES "trusts_trust" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Create model RolePermission
--
CREATE TABLE "trusts_rolepermission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "managed" bool NOT NULL, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Create model Role
--
CREATE TABLE "trusts_role" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "name" varchar(80) NOT NULL UNIQUE);
CREATE TABLE "trusts_role_groups" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "role_id" integer NOT NULL REFERENCES "trusts_role" ("id") DEFERRABLE INITIALLY DEFERRED, "group_id" integer NOT NULL REFERENCES "auth_group" ("id") DEFERRABLE INITIALLY DEFERRED);
--
-- Add field role to rolepermission
--
CREATE TABLE "new__trusts_rolepermission" ("id" integer NOT NULL PRIMARY KEY AUTOINCREMENT, "managed" bool NOT NULL, "permission_id" integer NOT NULL REFERENCES "auth_permission" ("id") DEFERRABLE INITIALLY DEFERRED, "role_id" integer NOT NULL REFERENCES "trusts_role" ("id") DEFERRABLE INITIALLY DEFERRED);
INSERT INTO "new__trusts_rolepermission" ("id", "managed", "permission_id", "role_id") SELECT "id", "managed", "permission_id", NULL FROM "trusts_rolepermission";
DROP TABLE "trusts_rolepermission";
ALTER TABLE "new__trusts_rolepermission" RENAME TO "trusts_rolepermission";
CREATE INDEX "trusts_trust_settlor_id_f8f950e4" ON "trusts_trust" ("settlor_id");
CREATE INDEX "trusts_trust_trust_id_9b89aad5" ON "trusts_trust" ("trust_id");
CREATE UNIQUE INDEX "trusts_trust_groups_trust_id_group_id_1f72e20c_uniq" ON "trusts_trust_groups" ("trust_id", "group_id");
CREATE INDEX "trusts_trust_groups_trust_id_36f34742" ON "trusts_trust_groups" ("trust_id");
CREATE INDEX "trusts_trust_groups_group_id_2e2f4c3a" ON "trusts_trust_groups" ("group_id");
CREATE INDEX "trusts_trustuserpermission_entity_id_5169cc9f" ON "trusts_trustuserpermission" ("entity_id");
CREATE INDEX "trusts_trustuserpermission_permission_id_8e9d1e68" ON "trusts_trustuserpermission" ("permission_id");
CREATE INDEX "trusts_trustuserpermission_trust_id_4097fe67" ON "trusts_trustuserpermission" ("trust_id");
CREATE UNIQUE INDEX "trusts_role_groups_role_id_group_id_f8121411_uniq" ON "trusts_role_groups" ("role_id", "group_id");
CREATE INDEX "trusts_role_groups_role_id_e52134cc" ON "trusts_role_groups" ("role_id");
CREATE INDEX "trusts_role_groups_group_id_7df413d4" ON "trusts_role_groups" ("group_id");
CREATE INDEX "trusts_rolepermission_permission_id_fc96b3e0" ON "trusts_rolepermission" ("permission_id");
CREATE INDEX "trusts_rolepermission_role_id_3a594439" ON "trusts_rolepermission" ("role_id");
--
-- Alter unique_together for trust (1 constraint(s))
--
CREATE UNIQUE INDEX "trusts_trust_settlor_id_title_1b123a1b_uniq" ON "trusts_trust" ("settlor_id", "title");
--
-- Alter unique_together for rolepermission (1 constraint(s))
--
CREATE UNIQUE INDEX "trusts_rolepermission_role_id_permission_id_aac32c60_uniq" ON "trusts_rolepermission" ("role_id", "permission_id");
--
-- Alter unique_together for trustuserpermission (1 constraint(s))
--
CREATE UNIQUE INDEX "trusts_trustuserpermission_trust_id_entity_id_permission_id_58872b33_uniq" ON "trusts_trustuserpermission" ("trust_id", "entity_id", "permission_id");
--
-- Raw Python operation
--
-- THIS OPERATION CANNOT BE WRITTEN AS SQL
COMMIT;

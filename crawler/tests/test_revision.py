"""Focused tests for first-class `revision` support.

Run from the project root:
    ./venv/bin/python -m unittest tests.test_revision

These tests are offline — they introspect the SQLAlchemy model/metadata and the
repository signature, and exercise the ORM object mapping. They do NOT open a DB
connection (the skills table uses Postgres JSONB, so a full round-trip would need a
real Postgres; that is covered by the standalone migration + manual ops, not here).
"""

import inspect
import unittest

from sqlalchemy import UniqueConstraint

from db.models import Skill
from db.repository import SkillRepository
from sources.base import SkillMetadata

UNIQUE_KEY = {"source", "source_id", "version", "artifact_hash"}


class RevisionModelTests(unittest.TestCase):
    def test_revision_column_exists_and_nullable(self):
        col = Skill.__table__.columns["revision"]
        self.assertTrue(col.nullable)
        self.assertFalse(col.primary_key)

    def test_revision_index_present(self):
        index_names = {ix.name for ix in Skill.__table__.indexes}
        self.assertIn("idx_skills_revision", index_names)

    def test_revision_not_in_unique_constraint(self):
        uniques = [c for c in Skill.__table__.constraints if isinstance(c, UniqueConstraint)]
        named = {c.name: {col.name for col in c.columns} for c in uniques}
        self.assertIn("uq_skill_version", named)
        # Uniqueness model is unchanged and excludes revision.
        self.assertEqual(named["uq_skill_version"], UNIQUE_KEY)
        self.assertNotIn("revision", named["uq_skill_version"])

    def test_orm_object_persists_revision_attribute(self):
        skill = Skill(
            source="github",
            source_id="owner/repo//skills/x",
            name="x",
            version="unversioned",
            revision="deadbeefcafe",
            artifact_hash="h",
        )
        self.assertEqual(skill.revision, "deadbeefcafe")

    def test_orm_revision_defaults_none(self):
        skill = Skill(source="clawhub", source_id="slug", name="n", version="1.0.0", artifact_hash="h")
        self.assertIsNone(skill.revision)


class RevisionContractTests(unittest.TestCase):
    def test_skillmetadata_has_revision_default_none(self):
        meta = SkillMetadata(source_id="slug", name="n")
        self.assertIsNone(meta.revision)
        meta2 = SkillMetadata(source_id="s", name="n", revision="abc")
        self.assertEqual(meta2.revision, "abc")

    def test_upsert_accepts_revision(self):
        params = inspect.signature(SkillRepository.upsert).parameters
        self.assertIn("revision", params)
        self.assertIsNone(params["revision"].default)


if __name__ == "__main__":
    unittest.main()

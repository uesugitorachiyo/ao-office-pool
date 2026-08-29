import json
import tempfile
import unittest
from pathlib import Path

from scripts.build_release import build_release


class BuildReleaseTests(unittest.TestCase):
    def setUp(self):
        self.temporary_directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve()); self.external_directory = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.root = Path(self.temporary_directory.name); self.source = self.root / "source"; self.source.mkdir(); self.output = self.root / "release.zip"; self.allowlist = self.root / "public-tree.json"
    def tearDown(self): self.external_directory.cleanup(); self.temporary_directory.cleanup()
    def allow(self): self.allowlist.write_text(json.dumps({"schema_version": 1, "tracked_root_files": ["README.md"], "tracked_roots": [], "excluded_roots": [], "excluded_names": [], "excluded_patterns": []}))
    def manifest(self, files=(), roots=(), **changes):
        data={"schema_version":1,"tracked_root_files":list(files),"tracked_roots":list(roots),"excluded_roots":[],"excluded_names":[],"excluded_patterns":[]}; data.update(changes); self.allowlist.write_text(json.dumps(data))
    def public(self): self.source.joinpath("README.md").write_text("public\n"); self.allow()

    def test_builds_existing_public_file(self): self.public(); self.assertEqual(build_release(self.source, self.output, self.allowlist), self.output)

    def test_archives_exact_allowlist_and_unique_names(self):
        self.source.joinpath("README.md").write_text("x"); (self.source / "scripts").mkdir(); self.source.joinpath("scripts/check.py").write_text("x"); self.manifest(("README.md","README.md"),("scripts",)); build_release(self.source,self.output,self.allowlist)
        import zipfile
        self.assertEqual(zipfile.ZipFile(self.output).namelist(),["README.md","scripts/check.py"])

    def test_rejects_parent_paths_and_symlink_members(self):
        self.manifest(("../private",));
        with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)
        target=self.root/"private"; target.write_text("x"); link=self.source/"README.md"
        try: link.symlink_to(target)
        except OSError as error: self.skipTest(str(error))
        self.manifest(("README.md",));
        with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)

    def test_rejects_tracked_root_file_beneath_symlinked_parent(self):
        target = Path(self.external_directory.name); target.joinpath("secret.txt").write_text("private\n"); link = self.source / "public-link"
        try: link.symlink_to(target, target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        self.manifest(("public-link/secret.txt",))
        with self.assertRaises(ValueError): build_release(self.source, self.output, self.allowlist)
        self.assertFalse(self.output.exists())

    def test_rejects_output_and_source_links(self):
        self.public(); output=self.root/"out.zip"; source_link=self.root/"source-link"
        try: output.symlink_to(self.root/"real.zip"); source_link.symlink_to(self.source,target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        with self.assertRaises(ValueError): build_release(self.source,output,self.allowlist)
        with self.assertRaises(ValueError): build_release(source_link,self.output,self.allowlist)

    def test_rejects_an_immediate_output_parent_link(self):
        self.public(); parent=self.root/"linked-parent"
        try: parent.symlink_to(Path(self.external_directory.name),target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        with self.assertRaises(ValueError): build_release(self.source,parent/"release.zip",self.allowlist)

    def test_keeps_repeated_build_bytes_stable(self):
        self.public(); build_release(self.source,self.output,self.allowlist); first=self.output.read_bytes(); build_release(self.source,self.output,self.allowlist); self.assertEqual(self.output.read_bytes(),first)

    def test_rejects_private_selected_members_before_output(self):
        (self.source/"scripts").mkdir(); self.source.joinpath("scripts/task.receipt.json").write_text("x"); self.manifest(roots=("scripts",),excluded_patterns=["*.receipt.json"])
        with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)
        self.assertFalse(self.output.exists())

    def test_governance_envelopes_tags_markers_and_keys_cannot_be_exported(self):
        prefix = ".ao/governance/office-pool/witness-0123456789abcdef0123456789abcdef"
        private = (
            prefix + ".json",
            prefix + ".hmac",
            prefix + ".consumed",
            prefix + ".revoked",
            "governance-witness.key",
        )
        for name in private:
            self.source.joinpath(name).parent.mkdir(parents=True, exist_ok=True)
            self.source.joinpath(name).write_text("private")
        self.manifest(files=private, excluded_roots=[".ao"], excluded_patterns=["*.key"])
        with self.assertRaises(ValueError):
            build_release(self.source, self.output, self.allowlist)
        self.assertFalse(self.output.exists())

    def test_rejects_schema_dot_and_wrong_kinds_but_allows_absence(self):
        self.source.joinpath("file").write_text("x"); (self.source/"directory").mkdir()
        for files,roots,changes in ((("file",),(),{"schema_version":2}), ((),(".",),{}), (("directory",),(),{}), ((),("file",),{})):
            self.manifest(files,roots,**changes)
            with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)
        self.manifest(("future",),("later",)); build_release(self.source,self.output,self.allowlist)

    def test_normalizes_zip_metadata(self):
        self.public(); build_release(self.source,self.output,self.allowlist)
        import zipfile
        archive=zipfile.ZipFile(self.output); info=archive.infolist()[0]; self.assertEqual(info.date_time,(1980,1,1,0,0,0)); self.assertEqual(info.create_system,3); self.assertEqual(info.external_attr >> 16,0o100644); self.assertEqual(info.extra,b""); self.assertEqual(info.flag_bits,0); self.assertEqual(archive.comment,b"")

    def test_rejects_noncanonical_schema_types_and_unknown_fields(self):
        self.source.joinpath("README.md").write_text("x")
        for changes in ({"tracked_root_files":["README.md/"]},{"tracked_root_files":["README.md//"]},{"excluded_names":None},{"unknown":True}):
            self.manifest(("README.md",), **changes)
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)

    def test_rejects_excluded_root_name_pattern_and_public_content_before_output(self):
        for path, changes in (("scripts/.local/x",{"excluded_roots":[".local"]}),("scripts/.env",{"excluded_names":[".env"]}),("scripts/x.receipt.json",{"excluded_patterns":["*.receipt.json"]})):
            self.write(path) if hasattr(self,"write") else None
            target=self.source/path; target.parent.mkdir(parents=True,exist_ok=True); target.write_text("x"); self.manifest(roots=("scripts",),**changes)
            with self.subTest(path=path):
                with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)
        self.source.joinpath("README.md").write_text("owner" + "Id: x"); self.manifest(("README.md",))
        with self.assertRaises(ValueError): build_release(self.source,self.output,self.allowlist)
        self.assertFalse(self.output.exists())

    def test_rejects_source_and_output_symlink_ancestors_beyond_three_levels(self):
        external = Path(self.external_directory.name); real_source = external / "deep" / "one" / "two" / "three" / "source"; real_source.mkdir(parents=True); real_source.joinpath("README.md").write_text("public\n")
        source_link_parent = self.root / "source-link"; output_link_parent = self.root / "output-link"
        try: source_link_parent.symlink_to(external / "deep", target_is_directory=True); output_link_parent.symlink_to(external, target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        self.allow()
        with self.assertRaises(ValueError): build_release(source_link_parent / "one" / "two" / "three" / "source", self.output, self.allowlist)

    def test_rejects_an_output_symlink_ancestor_beyond_three_levels(self):
        external = Path(self.external_directory.name); output_link_parent = self.root / "output-link"
        try: output_link_parent.symlink_to(external, target_is_directory=True)
        except OSError as error: self.skipTest(str(error))
        self.public()
        real_output_parent = output_link_parent / "one" / "two" / "three"; real_output_parent.mkdir(parents=True)
        with self.assertRaises(ValueError): build_release(self.source, real_output_parent / "release.zip", self.allowlist)


if __name__ == "__main__": unittest.main()

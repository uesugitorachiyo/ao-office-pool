from __future__ import annotations
import json,zipfile
from pathlib import Path,PurePosixPath
from scripts.scan_public_tree import scan_tree
def _chain(p):
 q=Path(p)
 while True:
  if q.is_symlink(): raise ValueError("link")
  if q==q.parent: break
  q=q.parent
def build_release(source:Path,output:Path,allowlist:Path)->Path:
 source,output=Path(source),Path(output); _chain(source); _chain(output)
 m=json.loads(Path(allowlist).read_text()); fields={"schema_version","tracked_root_files","tracked_roots","excluded_roots","excluded_names","excluded_patterns"}
 lists=fields-{"schema_version"}
 if type(m) is not dict or set(m)!=fields or type(m["schema_version"]) is not int or m["schema_version"]!=1 or any(type(m[x]) is not list or any(type(y) is not str for y in m[x]) for x in lists): raise ValueError("manifest")
 entries=[]
 for x in m["tracked_root_files"]:
  q=PurePosixPath(x)
  if x in {"","."} or "\\" in x or q.is_absolute() or x!=q.as_posix() or ".." in q.parts or len(x)>1 and x[1]==":": raise ValueError("path")
  p=source/x; _chain(p)
  if p.exists():
   if p.is_symlink() or not p.is_file(): raise ValueError("entry")
   entries.append(x)
 for x in m["tracked_roots"]:
  q=PurePosixPath(x)
  if x in {"","."} or "\\" in x or q.is_absolute() or x!=q.as_posix() or ".." in q.parts or len(x)>1 and x[1]==":": raise ValueError("root")
  p=source/x; _chain(p)
  if p.exists():
   if p.is_symlink() or not p.is_dir(): raise ValueError("entry")
   entries += [f.relative_to(source).as_posix() for f in p.rglob("*") if f.is_file()]
 entries=sorted(set(entries))
 if any(f.path in entries for f in scan_tree(source)): raise ValueError("private")
 with zipfile.ZipFile(output,"w",zipfile.ZIP_DEFLATED) as z:
  for x in entries:
   i=zipfile.ZipInfo(x,(1980,1,1,0,0,0)); i.compress_type=zipfile.ZIP_DEFLATED;i.create_system=3;i.external_attr=0o100644<<16;z.writestr(i,(source/x).read_bytes())
 return output

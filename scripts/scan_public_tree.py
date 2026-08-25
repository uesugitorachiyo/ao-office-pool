from __future__ import annotations
import ast, fnmatch, hashlib, json, os, re, sys
from dataclasses import dataclass
from pathlib import Path

ROOTS={".ao",".ao-mission",".local",".worktrees","build","dist","offices","operator-secrets","runtime","support-bundles","updates"}; PATS=("*.receipt.json","recovery-key*","*.pem","*.key","*.p12")
HASH_BOUND_PUBLIC_FILES={"packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json":"1a1c48a29c6b35713b08d733191e88887795fb8482054801900ae4b37e5bda3c"}
TRUSTED_PREVIEW_BINARIES={
 "components/ao2/v0.5.12/ao2.exe":"f2fb203040c0f67fe159e3f84cf84e5e8dcd3e882ff79f6abaa306e909d29dd1",
 "components/ao-mission/v0.1.6/ao-mission.exe":"46639c6389721dbc691d5e20f3d7478451bd160a7618352bff87917d2307d87b",
 "components/ao-command/v0.1.3/ao-command.exe":"3023530b6035e86e4167069840da4dcd61f2eeba261fca75a670415a12d71d55",
 "components/ao-atlas/v0.2.1/ao-atlas.exe":"d6d0bf089c8b04359fdd84bc9b825752eb2e4f5655ee6005c8f77a976295e521",
 "components/ao-forge/v0.1.5/forge.exe":"17545288d7c3ad62e0d091e282b363cd5e9c61af533cd3bb6dbaeb90f97aaed7",
 "components/ao-covenant/v0.1.1/ao-covenant_v0.1.1_windows_amd64.exe":"fd6e3a0033608d3f47dccb60f48191e4c4b2dc4fdce893c87d8ea96199610c5d",
 "components/ao2-control-plane/v0.1.19/ao2-cp-server.exe":"75c74af686ae6fb28d0566b66b908090567f848ecff1b6c1da4940691d416135",
 "components/ao-blueprint/git-ec6a80b60b54/ao-blueprint.exe":"8f4dd9766e77948e7688b0c80dc8e49ea1cd5fe7ab57be900c651ea2a2f4b4be",
 **{f"offices/O{office}/runtime/versions/v0.5.12/ao2.exe":"f2fb203040c0f67fe159e3f84cf84e5e8dcd3e882ff79f6abaa306e909d29dd1" for office in range(1,6)},
}
FIELD=r"(?im)(?:^[ \t]*(?:[-*+][ \t]+)?|[{\[(,][ \t]*)[\"']?"
RULES=(re.compile(FIELD+r"owner(?:_id|id)?[\"']?\s*[:=]"),re.compile(FIELD+r"(?:api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|recovery[_-]?key|(?:receipt|secret|token|password))[\w-]*[\"']?\s*[:=](?!\s*(?:Path|str)\b)"),re.compile(FIELD+r"(?:objective|transcript|model|resume|private[_-]?state)[\"']?\s*[:=](?!\s*str\b)"),re.compile(FIELD+r"(?:system\s+)?prompt[\"']?\s*[:=]"),re.compile(r"(?i)/(?:users|home|volumes)/[^/\s]+"),re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/][^\\/\s]+"))
@dataclass(frozen=True)
class Finding: path:str; rule:str; detail:str
def _preview_bindings(root:Path)->tuple[dict[str,tuple[int,str]],list[Finding]]:
 path=root/"developer-preview-manifest.json"
 if not path.exists(): return {},[]
 try:
  value=json.loads(path.read_text(encoding="utf-8"))
  if path.is_symlink() or not path.is_file() or set(value)!={"schema_version","label","architecture","runtime_version","files"} or type(value.get("schema_version")) is not int or value.get("schema_version")!=1 or value.get("label")!="developer-preview" or value.get("architecture")!="windows-x86_64" or not isinstance(value.get("runtime_version"),str) or not isinstance(value.get("files"),list): raise ValueError("manifest")
  bindings={}; binary_paths=set()
  folded=set()
  for row in value["files"]:
   if not isinstance(row,dict) or set(row)!={"path","sha256","size"}: raise ValueError("row")
   relative,digest,size=row["path"],row["sha256"],row["size"]
   if not isinstance(relative,str) or not relative or relative.startswith("/") or "\\" in relative or ":" in relative or any(part in {"",".",".."} for part in relative.split("/")) or relative.casefold() in folded or not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None or not isinstance(size,int) or isinstance(size,bool) or size<0: raise ValueError("identity")
   if Path(relative).suffix.casefold() in {".exe",".dll"}:
    if TRUSTED_PREVIEW_BINARIES.get(relative)!=digest: raise ValueError("untrusted binary")
    binary_paths.add(relative)
   folded.add(relative.casefold()); bindings[relative]=(size,digest)
  if binary_paths!=set(TRUSTED_PREVIEW_BINARIES): raise ValueError("binary set")
  return bindings,[]
 except (OSError,UnicodeDecodeError,json.JSONDecodeError,ValueError,TypeError): return {},[Finding("developer-preview-manifest.json","identity","private")]
def scan_tree(root:Path)->list[Finding]:
 root=Path(root)
 if root.is_symlink() or not root.is_dir(): raise ValueError("root")
 bindings,out=_preview_bindings(root); seen=set()
 def fail(e): raise e
 for d,ds,fs in os.walk(root,followlinks=False,onerror=fail):
  ds[:]=[x for x in ds if x!=".git"]
  for n in fs:
   p=Path(d)/n; r=p.relative_to(root).as_posix(); low=n.casefold()
   if p.is_symlink(): out.append(Finding(r,"symlink","private")); continue
   if r in bindings and r in TRUSTED_PREVIEW_BINARIES and p.suffix.casefold() in {".exe",".dll"}:
    data=p.read_bytes(); seen.add(r); size,digest=bindings[r]
    if len(data)!=size or hashlib.sha256(data).hexdigest()!=digest: out.append(Finding(r,"identity","private"))
    continue
   if r in HASH_BOUND_PUBLIC_FILES:
    if hashlib.sha256(p.read_bytes()).hexdigest()!=HASH_BOUND_PUBLIC_FILES[r]: out.append(Finding(r,"identity","private"))
    continue
   if any(x.casefold() in ROOTS for x in Path(r).parts) or low.startswith("._") or low.endswith((".pyc",".pyo")) or "__pycache__" in Path(r).parts or ".pytest_cache" in Path(r).parts or low==".env" or low.startswith(".env.") and low!=".env.example" or any(fnmatch.fnmatch(low,x) for x in PATS): out.append(Finding(r,"artifact","private")); continue
   t=p.read_text(errors="ignore"); texts=[t]
   if p.suffix==".py":
    try:
     tree=ast.parse(t); texts=[x.value for x in ast.walk(tree) if isinstance(x,ast.Constant) and isinstance(x.value,str)]; labels=[]
     for x in ast.walk(tree):
      targets=x.targets if isinstance(x,ast.Assign) else (x.target,) if isinstance(x,ast.AnnAssign) else ()
      for y in targets:
       if isinstance(y,ast.Name): labels.append(y.id)
       elif isinstance(y,ast.Attribute): labels.append(y.attr)
       elif isinstance(y,ast.Subscript) and isinstance(y.slice,ast.Constant) and isinstance(y.slice.value,str): labels.append(y.slice.value)
      if isinstance(x,ast.Dict): labels += [k.value for k in x.keys if isinstance(k,ast.Constant) and isinstance(k.value,str)]
      if isinstance(x,ast.keyword) and x.arg: labels.append(x.arg)
     texts += [x+"=" for x in labels if any(y.fullmatch(x+"=") for y in RULES)]
    except SyntaxError: pass
   if any(x.search(t) for t in texts for x in RULES): out.append(Finding(r,"content","private"))
 for missing in sorted(set(bindings)-seen):
  if Path(missing).suffix.casefold() in {".exe",".dll"} and not (root/missing).exists(): out.append(Finding(missing,"identity","private"))
 return sorted(out, key=lambda finding: (finding.path, finding.rule, finding.detail))
def main():
 try: findings=scan_tree(Path(sys.argv[1]) if len(sys.argv)>1 else Path("."))
 except (OSError,ValueError) as error:
  print(json.dumps({"error":"scan-failed","kind":type(error).__name__},sort_keys=True,separators=(",",":")))
  print("public-tree scan-error=1",file=sys.stderr)
  return 2
 for finding in findings:
  print(json.dumps({"detail":finding.detail,"path":finding.path,"rule":finding.rule},sort_keys=True,separators=(",",":")))
 print(f"public-tree findings={len(findings)}",file=sys.stderr)
 return int(bool(findings))
if __name__=="__main__": raise SystemExit(main())

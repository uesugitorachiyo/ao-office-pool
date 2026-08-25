from __future__ import annotations
import ast, fnmatch, hashlib, json, os, re, sys
from dataclasses import dataclass
from pathlib import Path

ROOTS={".ao",".ao-mission",".local",".worktrees","build","dist","offices","operator-secrets","runtime","support-bundles","updates"}; PATS=("*.receipt.json","recovery-key*","*.pem","*.key","*.p12")
HASH_BOUND_PUBLIC_FILES={"packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json":"1a1c48a29c6b35713b08d733191e88887795fb8482054801900ae4b37e5bda3c"}
FIELD=r"(?im)(?:^[ \t]*(?:[-*+][ \t]+)?|[{\[(,][ \t]*)[\"']?"
RULES=(re.compile(FIELD+r"owner(?:_id|id)?[\"']?\s*[:=]"),re.compile(FIELD+r"(?:api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|recovery[_-]?key|(?:receipt|secret|token|password))[\w-]*[\"']?\s*[:=](?!\s*(?:Path|str)\b)"),re.compile(FIELD+r"(?:objective|transcript|model|resume|private[_-]?state)[\"']?\s*[:=](?!\s*str\b)"),re.compile(FIELD+r"(?:system\s+)?prompt[\"']?\s*[:=]"),re.compile(r"(?i)/(?:users|home|volumes)/[^/\s]+"),re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/][^\\/\s]+"))
@dataclass(frozen=True)
class Finding: path:str; rule:str; detail:str
def _preview_bindings(root:Path)->tuple[dict[str,tuple[int,str]],list[Finding]]:
 path=root/"developer-preview-manifest.json"
 if not path.exists(): return {},[]
 try:
  value=json.loads(path.read_text(encoding="utf-8"))
  if path.is_symlink() or not path.is_file() or set(value)!={"schema_version","label","architecture","runtime_version","files"} or value.get("schema_version")!=1 or value.get("label")!="developer-preview" or value.get("architecture")!="windows-x86_64" or not isinstance(value.get("runtime_version"),str) or not isinstance(value.get("files"),list): raise ValueError("manifest")
  bindings={}
  folded=set()
  for row in value["files"]:
   if not isinstance(row,dict) or set(row)!={"path","sha256","size"}: raise ValueError("row")
   relative,digest,size=row["path"],row["sha256"],row["size"]
   if not isinstance(relative,str) or not relative or relative.startswith("/") or "\\" in relative or ":" in relative or any(part in {"",".",".."} for part in relative.split("/")) or relative.casefold() in folded or not isinstance(digest,str) or re.fullmatch(r"[0-9a-f]{64}",digest) is None or not isinstance(size,int) or isinstance(size,bool) or size<0: raise ValueError("identity")
   folded.add(relative.casefold()); bindings[relative]=(size,digest)
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
   if r in bindings and p.suffix.casefold() in {".exe",".dll"}:
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

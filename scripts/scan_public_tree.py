from __future__ import annotations
import ast, fnmatch, hashlib, os, re, sys
from dataclasses import dataclass
from pathlib import Path

ROOTS={".ao",".ao-mission",".local",".worktrees","build","dist","offices","operator-secrets","runtime","support-bundles","updates"}; PATS=("*.receipt.json","recovery-key*","*.pem","*.key","*.p12")
HASH_BOUND_PUBLIC_FILES={"packaging/runtime/ao-forge/docs/contracts/goal-run-v0.1.schema.json":"68a0fb154124fb4c219cc68eeffcc432e2c5c445765e9dbe24b19718fb98d74c"}
FIELD=r"(?im)(?:^[ \t]*(?:[-*+][ \t]+)?|[{\[(,][ \t]*)[\"']?"
RULES=(re.compile(FIELD+r"owner(?:_id|id)?[\"']?\s*[:=]"),re.compile(FIELD+r"(?:api[_-]?key|aws[_-]?secret[_-]?access[_-]?key|recovery[_-]?key|(?:receipt|secret|token|password))[\w-]*[\"']?\s*[:=](?!\s*(?:Path|str)\b)"),re.compile(FIELD+r"(?:objective|transcript|model|resume|private[_-]?state)[\"']?\s*[:=](?!\s*str\b)"),re.compile(FIELD+r"(?:system\s+)?prompt[\"']?\s*[:=]"),re.compile(r"(?i)/(?:users|home|volumes)/[^/\s]+"),re.compile(r"(?i)\b[a-z]:[\\/]+users[\\/][^\\/\s]+"))
@dataclass(frozen=True)
class Finding: path:str; rule:str; detail:str
def scan_tree(root:Path)->list[Finding]:
 root=Path(root)
 if root.is_symlink() or not root.is_dir(): raise ValueError("root")
 out=[]
 def fail(e): raise e
 for d,ds,fs in os.walk(root,followlinks=False,onerror=fail):
  ds[:]=[x for x in ds if x!=".git"]
  for n in fs:
   p=Path(d)/n; r=p.relative_to(root).as_posix(); low=n.casefold()
   if p.is_symlink(): out.append(Finding(r,"symlink","private")); continue
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
 return out
def main(): return int(bool(scan_tree(Path(sys.argv[1]) if len(sys.argv)>1 else Path("."))))
if __name__=="__main__": raise SystemExit(main())

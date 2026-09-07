import hashlib
import json
import os
import re
import shutil
import threading
import time
from datetime import datetime
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Any, Set

from constants import C, ICO
from loop import LoopSignal
from reporting import Finding
from storage import FailureMemory, JsonFileStore
from config import CONFIG, CONFIG_DIR, load_config, save_config
from logging_utils import log
from memory import is_bug_bounty_mode


class GoalNode:
    def __init__(self, node: str, parent: Optional[str], kind: str, description: str):
        self.node = node
        self.parent = parent
        self.kind = kind
        self.description = description
        self.active = True


class GoalTree:
    def __init__(self):
        self.nodes: Dict[str, GoalNode] = {}
        self._build()
    def _build(self):
        def add(node,parent,kind,desc): self.nodes[node]=GoalNode(node,parent,kind,desc)
        add("assessment",None,"root","Decide best path based on target model + evidence")
        add("recon_ports","assessment","recon","Discover services/ports and infer likely attack surface")
        add("recon_web","assessment","recon","Discover endpoints/tech stack for web/API targets")
        add("recon_ad","assessment","recon","Enumerate AD surface if applicable")
        add("exploit_web","assessment","exploit","Exploit discovered web/API weaknesses (auth, injection, RCE)")
        add("exploit_smb","assessment","exploit","Exploit SMB/windows weaknesses if exposed")
        add("validate","assessment","validate","Verify exploit impact and capture evidence")
        add("report","assessment","report","Produce final verified PoC/report")
        add("self_debug","assessment","diagnose","Run self-diagnostic and recovery procedures when stuck in a loop")
    def select_active_node(self,model,target_type,forced_exploit,loop_sig,autonomy_profile=None):
        if loop_sig.state=="hard": return "self_debug"
        if autonomy_profile:
            suggestion=autonomy_profile.recommend_goal(model,target_type,forced_exploit,loop_sig)
            if suggestion:return suggestion
        if forced_exploit:
            if any(p.get("port") in (80,443,8080,8443) for p in model.ports):return "exploit_web"
            if any(p.get("port")==445 for p in model.ports):return "exploit_smb"
            return "validate"
        ports={p.get("port") for p in model.ports}
        if any(p in ports for p in (80,443,8080,8443)):return "recon_web" if not model.endpoints else "exploit_web"
        if any(p in ports for p in (389,445,3389)):return "recon_ad" if 389 in ports else ("exploit_smb" if any(f.severity in ("medium","high","critical") for f in model.findings) else "validate")
        if not model.ports:return "recon_ports"
        return "exploit_web" if model.endpoints else "recon_ports"


class ConfidenceScorer:
    def score_action(self,category,model,failure_memory):
        blocked,_=failure_memory.is_blocked(category); base=0.62-(0.25 if blocked else 0)
        if category in ("web","web_scanner","web_dirbust","web_exploit") and any(p.get("port") in (80,443,8080,8443) for p in model.ports):base+=0.1
        if category=="smb" and any(p.get("port")==445 for p in model.ports):base+=0.1
        if category.startswith("subdomain") and model.subdomains:base+=0.07
        if any(f.severity in ("medium","high","critical") for f in model.findings):base+=0.05
        return max(.05,min(.98,base))
    def score_finding(self,evidence_text):
        if not evidence_text:return .05
        e=evidence_text.lower(); hits=sum(1 for k in ["vulnerable","exposed","success","rce","shell","root","flag{","ctf{","sql syntax","xss","unauthorized","authenticated","app_key",".env","private key","credentials"] if k in e)
        return max(.05,min(.98,.25+hits*.1))


class LoopDetector:
    def __init__(self): self.last_cmd_signatures=[]; self.last_goal_nodes=[]; self.last_categories=[]
    def observe(self,command,category,goal_node):
        s=re.sub(r'/tmp/[a-zA-Z0-9_\.\-]+','/tmp/_',command.strip()); s=re.sub(r'\s+',' ',s); sig=hashlib.sha256(s.encode(errors='ignore')).hexdigest()[:10]
        self.last_cmd_signatures.append(sig); self.last_cmd_signatures=self.last_cmd_signatures[-12:]
        self.last_goal_nodes.append(goal_node); self.last_goal_nodes=self.last_goal_nodes[-12:]
        self.last_categories.append(category); self.last_categories=self.last_categories[-12:]
    def detect(self,output_hash_recent,category_streak,goal_stagnant):
        if len(output_hash_recent)>=3 and output_hash_recent[-3:]==[output_hash_recent[-1]]*3:return LoopSignal(state='hard',category='output_hash',reason='Last 3 outputs identical')
        if len(output_hash_recent)>=2 and output_hash_recent[-2:]==[output_hash_recent[-1]]*2:return LoopSignal(state='soft',category='output_hash',reason='Last 2 outputs identical')
        cat=self._trailing_run(self.last_categories); goal=self._trailing_run(self.last_goal_nodes)
        if cat>=max(3,category_streak-1) and goal>=max(2,goal_stagnant-1):return LoopSignal(state='hard',category=self.last_categories[-1] if self.last_categories else 'stagnation',reason=f'Category streak {cat} + goal stagnant {goal}')
        if cat>=max(2,category_streak-2):return LoopSignal(state='soft',category=self.last_categories[-1] if self.last_categories else 'stagnation',reason=f'Category streak {cat}')
        return LoopSignal(state='none',reason='')
    @staticmethod
    def _trailing_run(seq):
        if not seq:return 0
        last=seq[-1]; n=0
        for x in reversed(seq):
            if x==last:n+=1
            else:break
        return n


@dataclass
class AutonomyProfile:
    goal_node:str='assessment'; pivot_bias:str='recon'; last_target:str=''; last_target_type:str=''; last_signal:str=''; last_learning_note:str=''; recent_signals:List[str]=field(default_factory=list); task_queue:List[Dict[str,str]]=field(default_factory=list); task_history:List[str]=field(default_factory=list); memory_counts:Dict[str,int]=field(default_factory=dict); failure_counts:Dict[str,int]=field(default_factory=dict); updated_ts:float=0.0
    def __post_init__(self):
        self.store=JsonFileStore(CONFIG_DIR/'autonomy_profile.json'); data=self.store.load()
        if data:self._load(data)
    def _load(self,data):
        for k in ('goal_node','pivot_bias','last_target','last_target_type','last_signal','last_learning_note','recent_signals','task_queue','task_history','memory_counts','failure_counts','updated_ts'):
            if k in data:setattr(self,k,data[k])
        self.recent_signals=list(self.recent_signals or [])[-12:]; self.task_queue=[t for t in (self.task_queue or []) if isinstance(t,dict)]; self.task_history=list(self.task_history or [])[-40:]
    def _save(self):
        try:self.store.save({'goal_node':self.goal_node,'pivot_bias':self.pivot_bias,'last_target':self.last_target,'last_target_type':self.last_target_type,'last_signal':self.last_signal,'last_learning_note':self.last_learning_note,'recent_signals':self.recent_signals[-12:],'task_queue':self.task_queue[-20:],'task_history':self.task_history[-40:],'memory_counts':self.memory_counts,'failure_counts':self.failure_counts,'updated_ts':self.updated_ts})
        except Exception as e:log(f'[AutonomyProfile] save failed: {e}')
    def observe(self,**kwargs):
        if kwargs.get('target'):self.last_target=kwargs['target']
        if kwargs.get('target_type'):self.last_target_type=kwargs['target_type']
        if kwargs.get('goal_node'):self.goal_node=kwargs['goal_node']
        if kwargs.get('loop_sig'):self.last_signal=str(kwargs['loop_sig'])[:120]
        if kwargs.get('memory_counts'):self.memory_counts=kwargs['memory_counts']
        if kwargs.get('failure_memory'):self.failure_counts=dict(kwargs['failure_memory'])
        self.updated_ts=time.time(); self._save(); return '\n'.join([f'GOAL: {self.goal_node}',f'PIVOT BIAS: {self.pivot_bias}',f'LAST TARGET: {self.last_target}',f'LOOP SIGNAL: {self.last_signal[:80]}'])
    @staticmethod
    def _task_key(task):return hashlib.sha256(f"{task.get('goal','')}|{task.get('category','')}|{task.get('command','')}|{task.get('mode','')}".encode(errors='ignore')).hexdigest()[:16]
    def push_tasks(self,tasks):
        if not tasks:return
        seen={self._task_key(t) for t in self.task_queue}; seen.update(self.task_history)
        for task in tasks:
            if not isinstance(task,dict):continue
            key=task.get('key') or self._task_key(task)
            if key in seen:continue
            t=dict(task);t['key']=key;self.task_queue.append(t);seen.add(key)
        self.task_queue=self.task_queue[-20:];self._save()
    def pop_task(self,key=None):
        if not self.task_queue:return None
        idx=0
        if key:
            for i,t in enumerate(self.task_queue):
                if (t.get('key') or self._task_key(t))==key:idx=i;break
            else:return None
        t=self.task_queue.pop(idx);k=t.get('key') or self._task_key(t);self.task_history.append(k);self.task_history=self.task_history[-40:];self._save();return t
    def clear_tasks(self):self.task_queue=[];self._save()
    def task_summary(self,limit=4):
        if not self.task_queue:return 'TASK QUEUE: empty'
        lines=['TASK QUEUE:']+[f"  [{t.get('mode','task')}] {t.get('goal','task')} -> {t.get('command','')[:140]}" for t in self.task_queue[:limit]]
        return '\n'.join(lines)
    def recommend_goal(self,model,target_type,forced_exploit,loop_sig):
        if loop_sig.state=='hard' or self.pivot_bias=='self_debug':return 'self_debug'
        if self.task_queue:
            mode=(self.task_queue[0].get('mode') or '').lower()
            if mode=='self_debug':return 'self_debug'
            if mode=='validate':return 'validate'
            if mode=='recon_web':return 'recon_web'
            if mode=='hypothesis':return 'exploit_web' if model.endpoints else 'validate'
        if any((f.severity if isinstance(f,Finding) else f.get('severity','info')) in ('critical','high') for f in model.findings):return 'validate'
        if forced_exploit:
            if any(p.get('port') in (80,443,8080,8443) for p in model.ports):return 'exploit_web'
            if any(p.get('port')==445 for p in model.ports):return 'exploit_smb'
            return 'validate'
        if self.pivot_bias=='validate' and model.findings:return 'validate'
        if self.pivot_bias=='exploit' and any(p.get('port') in (80,443,8080,8443) for p in model.ports):return 'exploit_web'
        if self.pivot_bias=='recon_web' and any(p.get('port') in (80,443,8080,8443) for p in model.ports):return 'recon_web' if not model.endpoints else 'exploit_web'
        if self.pivot_bias=='recon_ad' and any(p.get('port') in (389,445,3389) for p in model.ports):return 'recon_ad'
        return None


@dataclass
class MissionTask:
    key:str; goal:str; category:str; command:str; mode:str='recon'; reason:str=''; status:str='queued'; attempts:int=0; evidence:str=''; depends_on:List[str]=field(default_factory=list); created_ts:float=0.0; updated_ts:float=0.0
    @classmethod
    def from_dict(cls,d):return cls(key=d.get('key',''),goal=d.get('goal',''),category=d.get('category','analysis'),command=d.get('command',''),mode=d.get('mode','recon'),reason=d.get('reason',''),status=d.get('status','queued'),attempts=int(d.get('attempts',0) or 0),evidence=d.get('evidence',''),depends_on=list(d.get('depends_on',[]) or []),created_ts=float(d.get('created_ts',0) or 0),updated_ts=float(d.get('updated_ts',0) or 0))
    def to_dict(self):return asdict(self)

@dataclass
class VerificationVerdict:
    useful:bool; accepted:bool; reason:str=''; progress_delta:int=0; followups:List[Dict[str,str]]=field(default_factory=list)

class TaskGraph:
    def __init__(self,base_dir):
        self.store=JsonFileStore(base_dir/'mission_graph.json');self._data=self.store.load() or {'target':'','tasks':[],'history':[],'updated_ts':0.0};self._normalize()
    @staticmethod
    def _task_key(t):return hashlib.sha256(f"{t.get('goal','')}|{t.get('category','')}|{t.get('command','')}|{t.get('mode','')}".encode()).hexdigest()[:16]
    def _normalize(self):self._data['tasks']=[MissionTask.from_dict(t).to_dict() for t in (self._data.get('tasks',[]) or []) if isinstance(t,dict)];self._data['history']=list(self._data.get('history',[]) or [])[-80:]
    def _save(self):self._data['updated_ts']=time.time();self._normalize();self.store.save(self._data)
    def reset(self,target):self._data={'target':target,'tasks':[],'history':[],'updated_ts':time.time()};self._save()
    def add_tasks(self,tasks):
        existing={t.get('key') for t in self._data.get('tasks',[])};added=0
        for task in tasks or []:
            if not isinstance(task,dict):continue
            item=dict(task);item['key']=item.get('key') or self._task_key(item)
            if item['key'] in existing:continue
            item.setdefault('status','queued');item.setdefault('attempts',0);item.setdefault('created_ts',time.time());item.setdefault('updated_ts',time.time());self._data.setdefault('tasks',[]).append(MissionTask.from_dict(item).to_dict());existing.add(item['key']);added+=1
        if added:self._save()
        return added
    def open_tasks(self):return [MissionTask.from_dict(t) for t in self._data.get('tasks',[]) if t.get('status') in ('queued','running')]
    def next_task(self):
        for t in self._data.get('tasks',[]):
            if t.get('status')!='queued':continue
            t['status']='running';t['attempts']=int(t.get('attempts',0) or 0)+1;t['updated_ts']=time.time();self._data['history'].append({'ts':time.time(),'event':'start','key':t['key']});self._save();return MissionTask.from_dict(t)
        return None
    def mark(self,key,status,evidence='',reason=''):
        for t in self._data.get('tasks',[]):
            if t.get('key')==key:
                t['status']=status;t['evidence']=evidence[:300];t['reason']=reason[:180];t['updated_ts']=time.time();self._data['history'].append({'ts':time.time(),'event':status,'key':key,'reason':reason[:180]});self._save();return
    def summary(self,limit=4):
        ts=self.open_tasks()
        if not ts:return 'MISSION GRAPH: empty'
        return '\n'.join([f'MISSION GRAPH: {len(ts)} open task(s)']+[f'  [{t.mode}] {t.goal} -> {t.command[:120]}' for t in ts[:limit]])
    def has_open_work(self):return any(t.get('status') in ('queued','running') for t in self._data.get('tasks',[]))

class Verifier:
    def verify_progress(self,before_size,after_size,output,command):
        delta=max(0,after_size-before_size);low=(output or '').lower()
        if delta>0:return VerificationVerdict(True,True,f'model grew by {delta}',delta)
        if not output or not output.strip():return VerificationVerdict(False,False,'empty/no output',0)
        strong=('vulnerab','exploit','inject','rce','shell','root','sql syntax','xss','ssrf','idor','lfi','rfi','credential','password','token','secret','api key','private key','flag{','ctf{','open port','service detected','discovered endpoint','endpoint','new endpoint','exposed','success','unauthorized','authenticated')
        noise=('no results','not found','404','410','403','access denied','forbidden','timeout','timed out','connection refused','could not resolve','temporary failure','no such file','0 results')
        medium=('status code','status:','http','response','redirect','moved permanently','found')
        hs=any(s in low for s in strong);hn=any(s in low for s in noise);hm=any(s in low for s in medium)
        if hn and not hs:return VerificationVerdict(False,False,'noise/dead-end',0)
        if hs:return VerificationVerdict(True,True,'output contains strong evidence signals',0)
        if hm:return VerificationVerdict(False,False,'output lacks strong evidence',0)
        useful=any(s in low for s in ('endpoint','credential','password','token','secret','rce','sqli','xss','flag{','ctf{','vulnerab')) and not hn
        return VerificationVerdict(useful,useful,'output contains useful signal' if useful else 'output was noise/unclear',0)
    def verify_completion(self,all_exhausted,has_open_work,findings_count,iteration,min_iters):
        if has_open_work:return False,'mission still has open tasks'
        if not all_exhausted and iteration<min_iters and findings_count==0:return False,'mission not yet exhausted and no solid finding'
        if not all_exhausted and findings_count==0:return False,'no confirmed finding yet'
        return True,'completion accepted'

class AutoReplanner:
    def generate(self,agent,active_node,failure_reason=''):
        tasks=[];model=agent.model;host=agent._target_host();recent=[c.get('cmd','') for c in (agent.session.data.get('commands',[]) or [])[-20:] if isinstance(c,dict)];seen={agent._normalize_command(c) for c in recent if c};open_seen={agent._normalize_command(t.command) for t in agent.mission_graph.open_tasks() if t.command}
        def add(task):
            cmd=(task.get('command') or '').strip();cat=task.get('category') or agent._cmd_category(cmd)
            if not cmd or cat in (agent._banned_categories|agent._banned_plan_categories):return
            n=agent._normalize_command(cmd)
            if n and n not in seen and n not in open_seen:tasks.append(task);seen.add(n)
        if failure_reason:add({'goal':'recover from stalled decision loop','category':'analysis','mode':'self_debug','command':self.pick_fallback(agent),'reason':failure_reason[:180]})
        if not model.ports:add({'goal':'establish initial surface','category':'recon','mode':'recon','command':self.pick_fallback(agent),'reason':'No ports discovered yet.'})
        else:
            web=[p for p in model.ports if p.get('port') in (80,443,8080,8443)]
            if web and model.subdomains and not model.endpoints:
                sub=sorted(model.subdomains,key=agent._score_subdomain,reverse=True)[0];scheme='https' if any(p.get('port') in (443,8443) for p in web) else 'http';add({'goal':f'probe live host {sub}','category':'web','mode':'recon_web','command':f"curl -sik --max-time 5 '{scheme}://{sub}/' | head -30",'reason':'Subdomain exists but endpoints are missing.'})
            if model.endpoints:
                ep=max(model.endpoints[-10:],key=agent._score_endpoint);add({'goal':f"validate endpoint {ep.get('url','')}",'category':'scanner','mode':'validate','command':f"nuclei -u '{ep.get('url','')}' -severity medium,high,critical -silent",'reason':'Known endpoint should be validated.'})
        return tasks
    def pick_fallback(self,agent):
        host=agent._target_host();ports={int(p.get('port')) for p in agent.model.ports if p.get('port') is not None};banned=agent._banned_categories|agent._banned_plan_categories
        if not ports:return f'nmap -sV -Pn --top-ports 100 --max-rtt-timeout 500ms {host}'
        for p in (443,80,8080,8443,8000,3000,5000):
            if p in ports:
                scheme='https' if p in (443,8443) else 'http';cmd=f"curl -sik --max-time 5 '{scheme}://{host}:{p}/' | head -30"
                if agent._cmd_category(cmd) not in banned:return cmd
        return f'nmap -sV -Pn --top-ports 100 {host}'

class MissionManager:
    def __init__(self,agent):self.agent=agent;self.started_target=agent.target or ''
    def reset_for_target(self,target):
        if self.started_target and self.started_target!=target:self.agent.mission_graph.reset(target);self.agent.autonomy_profile.clear_tasks()
        self.started_target=target
    def seed(self,active_node,failure_reason=''):
        tasks=self.agent.auto_replanner.generate(self.agent,active_node,failure_reason);added=self.agent.mission_graph.add_tasks(tasks)
        if added:self.agent.autonomy_profile.push_tasks(tasks)
        return added
    def next_task(self,active_node,failure_reason=''):
        t=self.agent.mission_graph.next_task()
        if t:self.agent.autonomy_profile.pop_task(t.key);return t
        seeded=self.seed(active_node,failure_reason)
        if seeded:
            t=self.agent.mission_graph.next_task()
            if t:self.agent.autonomy_profile.pop_task(t.key);return t
        return None
    def should_accept_completion(self,completed,all_exhausted,iteration,findings_count):
        if not completed:return False,'AI has not requested completion'
        return self.agent.verifier.verify_completion(all_exhausted, self.agent.mission_graph.has_open_work(), findings_count, iteration, CONFIG.MIN_ITERATIONS if is_bug_bounty_mode() else 15)
    def record_outcome(self,command,result,before_size,after_size,category,active_node,task=None,is_plan=False):
        output=(result.text or '') if result else '';v=self.agent.verifier.verify_progress(before_size,after_size,output,command)
        if task:self.agent.mission_graph.mark(task.key,'done' if v.useful else 'failed',evidence=output[:300],reason=v.reason)
        if v.useful:
            follow=self.agent.auto_replanner.generate(self.agent,active_node)
            if follow:v.followups=follow;self.agent.mission_graph.add_tasks(follow);self.agent.autonomy_profile.push_tasks(follow)
        if is_plan and v.useful:self.agent._queue_autonomy_tasks(active_node,'mission manager planned follow-ups')
        return v
    def summary(self):
        ts=self.agent.mission_graph.open_tasks()
        if not ts:return 'MISSION MANAGER: no open tasks'
        return f'MISSION MANAGER: {len(ts)} open | next={ts[0].goal} | mode={ts[0].mode}'
    def observe(self,target,target_type,model,goal_node,loop_sig,failure_memory,memory_ready,memory_counts,self_summary,perf_summary,last_output=''):
        findings=list(model.findings);high=sum(1 for f in findings if (f.severity if isinstance(f,Finding) else f.get('severity','info')) in ('medium','high','critical'));ports=len(model.ports);eps=len(model.endpoints);subs=len(model.subdomains);failures=failure_memory._data.get('categories',{}) if failure_memory else {};ft=sum(int(v.get('count',0)) for v in failures.values()) if isinstance(failures,dict) else 0
        if loop_sig.state=='hard':bias='self_debug';signal=f'hard-loop:{loop_sig.category or "stagnation"}'
        elif high:bias='exploit';signal='confirmed-finding'
        elif eps>=8:bias='validate';signal='endpoint-rich'
        elif ports and any(p.get('port') in (80,443,8080,8443) for p in model.ports):bias='exploit' if eps else 'recon_web';signal='web-surface'
        elif any(p.get('port') in (389,445,3389) for p in model.ports):bias='recon_ad';signal='directory-or-windows-surface'
        elif ft>=8:bias='self_debug';signal='failure-pressure'
        elif subs and not eps:bias='recon_web';signal='subdomain-rich'
        else:bias='recon' if ports==0 else 'explore';signal='steady-state'
        self.goal_node=goal_node;self.pivot_bias=bias;self.last_target=target;self.last_target_type=target_type;self.last_signal=signal;self.last_learning_note=(last_output or perf_summary or self_summary or '').strip()[:180];self.memory_counts=dict(memory_counts or {});self.failure_counts={k:int(v.get('count',0)) for k,v in list(failures.items())[:8]} if isinstance(failures,dict) else {};self.updated_ts=time.time();self.recent_signals.append(f'{self.updated_ts:.0f}:{signal}');self.recent_signals=self.recent_signals[-12:];self._save();return f'AUTONOMY PROFILE:\n  goal={self.goal_node} bias={self.pivot_bias} signal={signal}\n  target={self.last_target} type={self.last_target_type} ports={ports} endpoints={eps} subdomains={subs} findings={len(findings)} high={high}'
    def recommend_goal(self,model,target_type,forced_exploit,loop_sig):return AutonomyProfile.recommend_goal(self,model,target_type,forced_exploit,loop_sig)

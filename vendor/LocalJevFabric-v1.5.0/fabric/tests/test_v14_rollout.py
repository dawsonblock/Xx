import json
from pathlib import Path

import pytest

from local_jev_fabric.benchmark import score_case
from local_jev_fabric.config import BackendConfig, FabricConfig
from local_jev_fabric.drift import DriftMonitor, build_profiles
from local_jev_fabric.outcomes import OutcomeStore, create_dataset_snapshot
from local_jev_fabric.registry import RouteBinding, TaskRegistry, question_signature
from local_jev_fabric.router import FabricRouter


class RolloutClient:
    def __init__(self):
        self.calls=[]
    async def manifest(self, backend):
        return {
            'served_model': backend.model,
            'artifact_bundle_sha256':'a'*64,
            'backend_fingerprint_sha256':'f'*64,
            'calibration_evidence_sha256':'c'*64,
            'score_semantics':'calibrated','legacy_artifacts_enabled':False,
        }
    async def ask(self, backend, payload):
        self.calls.append((backend.name,tuple(payload['questions'])))
        # candidate says no, baseline says yes; makes shadow behavior observable.
        p = 0.1 if backend.name == 'anyjev' else 0.9
        return {'model':backend.model,'answers':{qid:{'type':'noul','noul':p} for qid in payload['questions']},'usage':{'input_tokens':1,'output_tokens':0}}


def cfg():
    return FabricConfig(host='127.0.0.1',port=8090,model='fabric',api_key=None,registry_path=None,
        backends=(
            BackendConfig('anyjev','http://any','a',role='specialist',score_semantics='calibrated'),
            BackendConfig('laya','http://laya','l'),
            BackendConfig('llm2jev','http://llm','q'),
        ),generalist_order=('laya','llm2jev'))


def test_route_binding_rollout_guards():
    with pytest.raises(ValueError,match='baseline_backend'):
        RouteBinding('anyjev',deployment_stage='shadow')
    with pytest.raises(ValueError,match='0 < canary_percent'):
        RouteBinding('anyjev',deployment_stage='canary',baseline_backend='laya',canary_percent=100)
    with pytest.raises(ValueError,match='only stable deployments'):
        RouteBinding('anyjev',deployment_stage='shadow',baseline_backend='laya',direct_authorized=True)


@pytest.mark.asyncio
async def test_shadow_candidate_never_controls_live_answer():
    q={'type':'noul','instructions':'Known?'}
    reg=TaskRegistry(); reg.register(q,'anyjev',deployment_stage='shadow',baseline_backend='laya')
    router=FabricRouter(cfg(),reg,client=RolloutClient())
    result,trace=await router.evaluate_detailed({'state':'private','model':'fabric','questions':{'x':q}},request_id='shadow-1')
    assert result['answers']['x']['noul']==0.9
    assert trace['provenance']['x']=='laya'
    assert len(trace['shadow'])==1
    row=trace['shadow'][0]
    assert row['shadow_backend']=='anyjev' and row['production_backend']=='laya'
    assert row['agreement'] is False


def test_canary_assignment_is_deterministic_and_has_both_arms():
    q={'type':'noul','instructions':'Known?'}
    reg=TaskRegistry(); reg.register(q,'anyjev',deployment_stage='canary',baseline_backend='laya',canary_percent=50)
    router=FabricRouter(cfg(),reg,client=RolloutClient())
    first=router.plan({'x':q},request_id='same')[0]
    second=router.plan({'x':q},request_id='same')[0]
    assert first.canary_selected==second.canary_selected
    values={router.plan({'x':q},request_id=f'r-{i}')[0].canary_selected for i in range(100)}
    assert values=={True,False}


@pytest.mark.asyncio
async def test_drift_can_disable_fail_closed_specialist():
    q={'type':'noul','instructions':'Known?'}; sig=question_signature(q)
    profile={'version':1,'profiles':{sig:{'samples':100,'score_mean':0.95,'score_std':0.02,'answer_distribution':{'yes':1.0}}}}
    drift=DriftMonitor(profile,window=5,min_samples=5,degraded_z=1.5,disabled_z=2.0,degraded_js=.1,disabled_js=.2)
    # Seed a clear distribution shift before routing.
    for _ in range(5): drift.observe(sig,score=.51,answer_key='no')
    reg=TaskRegistry(); reg.register(q,'anyjev',fallback_policy='fail_closed')
    router=FabricRouter(cfg(),reg,client=RolloutClient(),drift=drift)
    with pytest.raises(ValueError,match='disabled by drift'):
        router.plan({'x':q},request_id='r')


def test_drift_profile_builder():
    p=build_profiles([
        {'signature':'s','score':.9,'answer_key':'yes'},
        {'signature':'s','score':.8,'answer_key':'yes'},
        {'signature':'s','score':.7,'answer_key':'no'},
    ])
    assert p['profiles']['s']['samples']==3
    assert p['profiles']['s']['answer_distribution']['yes']==pytest.approx(2/3)


def test_outcome_store_and_immutable_dataset_snapshot(tmp_path):
    promo=tmp_path/'promotion.jsonl'; out=tmp_path/'outcomes.jsonl'; ds=tmp_path/'snapshot'
    q={'type':'noul','instructions':'Q?'}; sig=question_signature(q)
    promo.write_text(json.dumps({'version':1,'request_id':'r1','question_id':'q','signature':sig,'question':q,'backend':'laya','score':.9,'score_semantics':'concentration'})+'\n')
    store=OutcomeStore(str(out)); store.append({'request_id':'r1','question_id':'q','signature':sig,'evidence_sha256':'e'*64,'correct':True,'expected_key':'yes','label_source':'test'})
    manifest=create_dataset_snapshot(promotion_journal=promo,outcomes=out,output_dir=ds)
    assert manifest['examples']==1
    example=json.loads((ds/'examples.jsonl').read_text().strip())
    assert example['split'] in {'train','validation','qualification','audit_holdout'}
    assert example['label']['expected_key']=='yes'
    with pytest.raises(ValueError,match='must not already contain'):
        create_dataset_snapshot(promotion_journal=promo,outcomes=out,output_dir=ds)


def test_benchmark_case_scoring_and_false_direct_input():
    case={'questions':{'a':{'type':'choice','criteria':{'x':'x','y':'y'}}},'expected':{'a':'x'},'allow_direct':False}
    response={'answers':{'a':{'type':'choice','choice':'x','probabilities':{'x':.9,'y':.1},'confidence':.9}},'fabric':{'direct_authorized':True}}
    correct,total,direct=score_case(case,response)
    assert (correct,total,direct)==(1,1,True)


def test_outcome_store_is_idempotent_and_rejects_conflicts(tmp_path):
    path=tmp_path/'o.jsonl'; store=OutcomeStore(str(path)); sig='a'*64
    value={'request_id':'r','question_id':'q','signature':sig,'evidence_sha256':'e'*64,'correct':True,'expected_key':'yes'}
    first=store.append(value); second=store.append(value)
    assert first==second
    assert len(path.read_text().splitlines())==1
    with pytest.raises(ValueError,match='conflicting outcome'):
        store.append({**value,'correct':False})


def test_rollout_cli_stages_and_rolls_back_bad_canary(tmp_path, monkeypatch):
    import argparse
    import local_jev_fabric.rollout_cli as rc
    from local_jev_fabric.registry import atomic_write_json
    monkeypatch.setenv('FABRIC_REGISTRY_HMAC_KEY','secret')
    q={'type':'noul','instructions':'Canary?'}; sig=question_signature(q)
    reg=TaskRegistry(); reg.register(q,'anyjev'); path=tmp_path/'reg.json'; atomic_write_json(path,reg.to_dict(hmac_key='secret'))
    common=dict(registry=str(path),registry_hmac_key_env='FABRIC_REGISTRY_HMAC_KEY')
    rc.cmd_shadow(argparse.Namespace(**common,signature=sig,baseline_backend='laya'))
    r=TaskRegistry.load(str(path),hmac_key='secret',require_hmac=True); assert r.routes[sig].deployment_stage=='shadow'
    rc.cmd_canary(argparse.Namespace(**common,signature=sig,baseline_backend='laya',percent=10.0))
    r=TaskRegistry.load(str(path),hmac_key='secret',require_hmac=True); assert r.routes[sig].deployment_stage=='canary'
    shadow=tmp_path/'shadow.jsonl'; outcomes=tmp_path/'out.jsonl'
    rows=[]; labels=[]
    for i in range(5):
        rows.append({'version':1,'request_id':f'r{i}','question_id':'q','signature':sig,'candidate_backend':'anyjev','baseline_backend':'laya','production_backend':'anyjev','shadow_backend':'laya','production_key':'no','shadow_key':'yes'})
        labels.append({'version':1,'request_id':f'r{i}','question_id':'q','signature':sig,'expected_key':'yes'})
    shadow.write_text('\n'.join(json.dumps(x) for x in rows)+'\n'); outcomes.write_text('\n'.join(json.dumps(x) for x in labels)+'\n')
    with pytest.raises(SystemExit) as exc:
        rc.cmd_evaluate(argparse.Namespace(**common,signature=sig,shadow_journal=str(shadow),outcomes=str(outcomes),min_samples=5,max_error_delta=.1,rollback=True))
    assert exc.value.code==2
    rolled=TaskRegistry.load(str(path),hmac_key='secret',require_hmac=True).routes[sig]
    assert rolled.backend=='laya' and rolled.deployment_stage=='stable' and rolled.direct_authorized is False

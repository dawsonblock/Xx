import json
from pathlib import Path

import pytest

from local_jev_fabric.artifact_signing import (
    attestation_digest, create_attestation, generate_keypair, verify_attestation,
)
from local_jev_fabric.capabilities import CapabilityRegistry
from local_jev_fabric.escalation import EscalationPolicy
from local_jev_fabric.independent_qualification import build_payload, digest as iq_digest, sign_payload, verify as verify_iq
from local_jev_fabric.promotion import QualificationPolicy
from local_jev_fabric.registry import TaskRegistry, canonical_json, question_signature
from local_jev_fabric.replay import ReplayStore, incident_bundle, verify_record
from local_jev_fabric.telemetry import TelemetrySink


def test_capability_ranking_filters_unsupported_and_uses_cost_accuracy(tmp_path):
    p=tmp_path/'caps.json'
    p.write_text(json.dumps({'version':1,'backends':{
        'tiny':{'question_types':['noul'],'expected_accuracy':{'noul':.82},'p95_ms':20,'cost_units':.1},
        'strong':{'question_types':['noul','choice'],'expected_accuracy':{'noul':.97,'choice':.93},'p95_ms':100,'cost_units':1.0},
        'choice-only':{'question_types':['choice'],'expected_accuracy':{'choice':.95},'p95_ms':40,'cost_units':.2},
    }}))
    caps=CapabilityRegistry.load(str(p))
    # High error cost chooses the stronger noul model despite its added compute.
    assert caps.rank_names(('tiny','strong','choice-only'),'noul',error_cost=10,cost_weight=.02)[0]=='strong'
    # The noul-only model is excluded for choice; both eligible choice models remain.
    ranked=caps.rank_names(('tiny','strong','choice-only'),'choice',error_cost=2,cost_weight=.1)
    assert 'tiny' not in ranked and set(ranked)=={'strong','choice-only'}


def test_cost_aware_escalation_uses_calibrated_uncertainty(tmp_path):
    p=tmp_path/'caps.json'; p.write_text(json.dumps({'version':1,'backends':{
        'cheap':{'expected_accuracy':{'noul':.8},'p95_ms':20,'cost_units':.1},
        'strong':{'expected_accuracy':{'noul':.98},'p95_ms':100,'cost_units':1.0},
    }}))
    caps=CapabilityRegistry.load(str(p)); policy=EscalationPolicy(error_cost=10,cost_weight=.01,latency_weight=.001)
    assert policy.should_escalate(score=.60,score_semantics='calibrated',current_backend='cheap',next_backend='strong',question_type='noul',capabilities=caps)
    assert not policy.should_escalate(score=.995,score_semantics='calibrated',current_backend='cheap',next_backend='strong',question_type='noul',capabilities=caps)


def test_ed25519_artifact_attestation_roundtrip_and_tamper(tmp_path):
    priv=tmp_path/'signing.pem'; pub=tmp_path/'signing.pub.pem'; generate_keypair(priv,pub)
    value=create_attestation(digest='sha256:'+'a'*64,kind='anyjev-artifact-bundle',private_key_path=priv,metadata={'build':'v1'})
    assert verify_attestation(value,pub,expected_kind='anyjev-artifact-bundle')['digest']=='sha256:'+'a'*64
    assert attestation_digest(value).startswith('sha256:')
    tampered=json.loads(json.dumps(value)); tampered['digest']='sha256:'+'b'*64
    with pytest.raises(ValueError,match='signature verification failed'):
        verify_attestation(tampered,pub)


def test_independent_qualification_is_bound_to_evaluator_key(tmp_path):
    priv=tmp_path/'eval.pem'; pub=tmp_path/'eval.pub.pem'; generate_keypair(priv,pub)
    q={'type':'noul','instructions':'Safe?'}
    cases=[{'state':'x','question':q,'expected_key':'yes'} for _ in range(5)]
    manifest={'served_model':'anyjev','artifact_bundle_sha256':'a'*64,'backend_fingerprint_sha256':'f'*64,'calibration_evidence_sha256':'c'*64}
    policy=QualificationPolicy(min_samples=5,min_accuracy=.8,max_ece=1,max_brier=1,max_wilson_error_upper=1,operating_threshold=.8)
    payload=build_payload(cases=cases,case_digest='sha256:'+'e'*64,records=[(.9,True)]*5,manifest=manifest,task_id='safe.v1',evaluator_id='independent-lab',policy=policy)
    signed=sign_payload(payload,priv); verified=verify_iq(signed,pub)
    assert verified['qualified'] is True and verified['question_signature']==question_signature(q)
    assert iq_digest(signed).startswith('sha256:')


def test_replay_store_excludes_raw_state_and_incident_bundle_verifies(tmp_path):
    path=tmp_path/'replays.jsonl'; store=ReplayStore(str(path))
    q={'type':'noul','instructions':'Q?'}; trace={'request_sha256':'a'*64,'plan_sha256':'b'*64,'evidence_sha256':'c'*64,'direct_authorized':False,'decisions':{}}
    row=store.append(request_id='r1',request={'model':'fabric','state':{'secret':'DO-NOT-LOG'},'questions':{'q':q}},response={'answers':{}},trace=trace,registry_payload={'version':5,'revision':1,'routes':{}})
    assert row and 'DO-NOT-LOG' not in path.read_text()
    assert verify_record(row,state={'secret':'DO-NOT-LOG'})['state_matches'] is True
    bundle=tmp_path/'incident.zip'; digest=incident_bundle(row=row,output=bundle)
    assert bundle.exists() and digest.startswith('sha256:')


def test_telemetry_is_content_free(tmp_path):
    path=tmp_path/'otel.jsonl'; sink=TelemetrySink(str(path))
    sink.emit_request(request_id='r',duration_ms=12.3,trace={'request_sha256':'a'*64,'plan_sha256':'b'*64,'evidence_sha256':'c'*64,'direct_authorized':False,'decisions':{'q':{'backend':'laya'}},'attempts':[],'state':'SECRET'})
    text=path.read_text(); row=json.loads(text)
    assert 'SECRET' not in text
    assert row['attributes']['jev.backends']==['laya']


def test_v4_direct_registry_must_be_rebound_for_v15(tmp_path):
    import hashlib
    q={'type':'noul','instructions':'Legacy direct?'}
    payload={'version':4,'revision':1,'updated_at':'2026-09-28T00:00:00Z','routes':{question_signature(q):{
        'backend':'anyjev','fallback_policy':'fail_closed','direct_authorized':True,'min_score':.9,
        'artifact_digest':'sha256:'+'a'*64,'backend_fingerprint':'sha256:'+'f'*64,'calibration_digest':'sha256:'+'c'*64,
        'qualification_digest':'sha256:'+'1'*64,'promotion_id':'sha256:'+'1'*64,
    }}}
    value={**payload,'integrity':{'payload_sha256':hashlib.sha256(canonical_json(payload).encode()).hexdigest()}}
    p=tmp_path/'reg.json'; p.write_text(json.dumps(value))
    with pytest.raises(ValueError,match='v1.5 independent qualification'):
        TaskRegistry.load(str(p))

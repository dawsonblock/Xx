from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Any, Mapping

from .client import BackendError, SystemOneClient
from .capabilities import CapabilityRegistry
from .escalation import EscalationPolicy
from .config import FabricConfig
from .drift import DriftMonitor
from .health import CircuitBreaker
from .registry import RouteBinding, TaskRegistry, canonical_json, question_signature
from .schema import AnswerValidationError, validate_answer
from .shadow import answer_key


@dataclass(frozen=True)
class QuestionRoute:
    question_id: str
    signature: str
    preferred: str
    registered: bool
    task_id: str | None = None
    binding: RouteBinding | None = None
    deployment_stage: str = "stable"
    candidate_backend: str | None = None
    baseline_backend: str | None = None
    shadow_backend: str | None = None
    canary_selected: bool = False
    drift_status: str = "normal"
    question_type: str = "noul"


def answer_concentration(answer: Mapping[str, Any]) -> float:
    """Return answer concentration. This is not automatically probability-of-correctness."""
    typ = answer.get("type")
    if typ in {"choice", "score"}:
        try:
            return float(answer.get("confidence", 0.0))
        except (TypeError, ValueError):
            return 0.0
    if typ == "noul":
        try:
            p = float(answer.get("noul"))
        except (TypeError, ValueError):
            return 0.0
        return max(p, 1.0 - p) if 0.0 <= p <= 1.0 else 0.0
    return 0.0


def _canary_selected(request_id: str | None, signature: str, percent: float) -> bool:
    seed = f"{request_id or 'preview'}:{signature}".encode("utf-8")
    bucket = int.from_bytes(hashlib.sha256(seed).digest()[:8], "big") / float(2**64)
    return bucket * 100.0 < float(percent)


class FabricRouter:
    def __init__(self, config: FabricConfig, registry: TaskRegistry, client: SystemOneClient | None = None,
                 drift: DriftMonitor | None = None):
        self.config = config
        self.registry = registry
        self.client = client or SystemOneClient()
        self.backends = config.by_name
        self.breaker = CircuitBreaker(config.backends)
        self.drift = drift or DriftMonitor()
        self._semaphores = {b.name: asyncio.Semaphore(b.max_concurrency) for b in config.backends}
        self._attestations: dict[str, tuple[float, dict[str, Any]]] = {}
        self.capabilities = CapabilityRegistry.load(config.capability_manifest_path)
        self.escalation = EscalationPolicy(
            error_cost=config.escalation_error_cost, cost_weight=config.escalation_cost_weight,
            latency_weight=config.escalation_latency_weight, min_expected_gain=config.escalation_min_expected_gain,
        )

    def plan(self, questions: Mapping[str, Any], *, request_id: str | None = None) -> list[QuestionRoute]:
        first_generalist = self.config.generalist_order[0]
        routes: list[QuestionRoute] = []
        for qid, question in questions.items():
            if not isinstance(question, Mapping):
                raise ValueError(f"question {qid!r} must be an object")
            sig = question_signature(question)
            qtype = str(question.get("type") or "")
            ranked_generalists = self.capabilities.rank_names(
                self.config.generalist_order, qtype, state_chars=None,
                error_cost=self.config.escalation_error_cost, cost_weight=self.config.escalation_cost_weight,
                latency_weight=self.config.escalation_latency_weight,
            )
            if not ranked_generalists:
                raise ValueError(f"no configured generalist declares support for question type {qtype!r}")
            first_generalist = ranked_generalists[0]
            binding = self.registry.lookup_any(question)
            if binding is not None and not binding.active():
                raise ValueError(f"registered task binding for {qid!r} is inactive or expired; refusing generalist downgrade")
            drift_status = self.drift.status(sig)
            if binding is not None and drift_status == "disabled":
                if binding.direct_authorized or binding.fallback_policy == "fail_closed":
                    raise ValueError(f"registered task binding for {qid!r} is disabled by drift; refusing unsafe downgrade")
                routes.append(QuestionRoute(
                    question_id=str(qid), signature=sig, preferred=first_generalist, registered=True,
                    task_id=binding.task_id, binding=binding, deployment_stage=binding.deployment_stage,
                    candidate_backend=binding.backend, baseline_backend=binding.baseline_backend,
                    drift_status=drift_status, question_type=qtype,
                ))
                continue

            if binding is None:
                routes.append(QuestionRoute(
                    question_id=str(qid), signature=sig, preferred=first_generalist, registered=False,
                    drift_status=drift_status, question_type=qtype,
                ))
                continue

            if binding.backend not in self.backends:
                raise ValueError(f"registry routes {qid!r} to unknown backend {binding.backend!r}")
            if binding.backend_model and binding.backend_model != self.backends[binding.backend].model:
                raise ValueError(
                    f"registry task {binding.task_id or qid!r} is bound to model {binding.backend_model!r}, "
                    f"configured backend {binding.backend!r} serves {self.backends[binding.backend].model!r}"
                )

            stage = binding.deployment_stage
            candidate = binding.backend
            baseline = binding.baseline_backend
            shadow: str | None = None
            selected = False
            if stage == "stable":
                preferred = candidate
            else:
                if baseline not in self.backends:
                    raise ValueError(f"registry task {binding.task_id or qid!r} references unknown baseline backend {baseline!r}")
                if stage == "shadow":
                    preferred = str(baseline)
                    shadow = candidate
                else:
                    selected = _canary_selected(request_id, sig, binding.canary_percent)
                    preferred = candidate if selected else str(baseline)
                    shadow = str(baseline) if selected else candidate

            routes.append(QuestionRoute(
                question_id=str(qid), signature=sig, preferred=preferred, registered=True,
                task_id=binding.task_id, binding=binding, deployment_stage=stage,
                candidate_backend=candidate, baseline_backend=baseline, shadow_backend=shadow,
                canary_selected=selected, drift_status=drift_status, question_type=qtype,
            ))
        return routes

    def _fallback_chain(self, route: QuestionRoute) -> tuple[str, ...]:
        if route.binding and route.deployment_stage == "stable" and route.binding.fallback_policy == "fail_closed":
            return (route.preferred,)
        chain: list[str] = [route.preferred]
        # A selected canary candidate may fall back to its production baseline. An experimental
        # candidate is never used as fallback when baseline traffic was selected.
        if route.deployment_stage == "canary" and route.canary_selected and route.baseline_backend:
            if route.baseline_backend not in chain:
                chain.append(route.baseline_backend)
        ranked = self.capabilities.rank_names(
            self.config.generalist_order, route.question_type,
            error_cost=self.config.escalation_error_cost, cost_weight=self.config.escalation_cost_weight,
            latency_weight=self.config.escalation_latency_weight,
        )
        for name in ranked:
            if name not in chain:
                chain.append(name)
        return tuple(chain)

    async def _authority_attestation(self, route: QuestionRoute, backend_name: str) -> tuple[bool, dict[str, bool]]:
        binding = route.binding
        backend = self.backends[backend_name]
        checks = {
            "binding_direct_authorized": bool(binding and binding.direct_authorized),
            "deployment_stable": bool(binding and binding.deployment_stage == "stable"),
            "drift_normal": route.drift_status == "normal" and self.drift.status(route.signature) == "normal",
            "registry_integrity": bool(self.registry.integrity_verified),
            "configured_calibrated": backend.score_semantics == "calibrated",
            "manifest_available": False,
            "served_model": False,
            "artifact": False,
            "backend_fingerprint": False,
            "calibration_evidence": False,
            "qualification_bound": bool(binding and binding.qualification_digest and binding.promotion_id),
            "independent_qualification_bound": bool(binding and binding.independent_qualification_digest),
            "artifact_attestation_bound": bool(binding and binding.artifact_attestation_digest),
            "manifest_calibrated": False,
            "legacy_disabled": False,
        }
        if (not binding or not binding.direct_authorized or binding.deployment_stage != "stable" or
                not checks["drift_normal"] or not self.registry.integrity_verified or backend.score_semantics != "calibrated"):
            return False, checks
        manifest_fn = getattr(self.client, "manifest", None)
        if not callable(manifest_fn):
            return False, checks
        now = time.monotonic()
        cached = self._attestations.get(backend_name)
        if cached is not None and cached[0] >= now:
            manifest = cached[1]
        else:
            try:
                manifest = await manifest_fn(backend)
            except BackendError:
                return False, checks
            self._attestations[backend_name] = (now + backend.attestation_ttl_s, dict(manifest))
        checks["manifest_available"] = True
        artifact = str(manifest.get("artifact_bundle_sha256") or "")
        fingerprint = str(manifest.get("backend_fingerprint_sha256") or "")
        calibration = str(manifest.get("calibration_evidence_sha256") or "")
        served_model = str(manifest.get("served_model") or "")
        expected_artifact = str(binding.artifact_digest or "").removeprefix("sha256:")
        expected_fingerprint = str(binding.backend_fingerprint or "").removeprefix("sha256:")
        expected_calibration = str(binding.calibration_digest or "").removeprefix("sha256:")
        checks["served_model"] = served_model == backend.model
        checks["legacy_disabled"] = not bool(manifest.get("legacy_artifacts_enabled", False))
        checks["manifest_calibrated"] = manifest.get("score_semantics") == "calibrated"
        checks["artifact"] = bool(artifact and hmac.compare_digest(artifact, expected_artifact))
        checks["backend_fingerprint"] = bool(fingerprint and hmac.compare_digest(fingerprint, expected_fingerprint))
        checks["calibration_evidence"] = bool(calibration and hmac.compare_digest(calibration, expected_calibration))
        return all(checks.values()), checks

    @staticmethod
    def _usage(data: Mapping[str, Any]) -> tuple[int, int]:
        usage = data.get("usage")
        if not isinstance(usage, Mapping):
            return 0, 0
        def n(key: str) -> int:
            value = usage.get(key, 0)
            return int(value) if isinstance(value, (int, float)) and value >= 0 else 0
        return n("input_tokens"), n("output_tokens")

    async def _ask_group(self, backend_name: str, qids: list[str], payload: Mapping[str, Any],
                         questions: Mapping[str, Any]) -> tuple[str, list[str], dict[str, Any] | None, str | None, int]:
        started = time.perf_counter()
        if not self.breaker.allow(backend_name):
            elapsed = round((time.perf_counter() - started) * 1000)
            return backend_name, qids, None, "circuit_open", elapsed
        backend = self.backends[backend_name]
        sub = {"state": payload.get("state"), "model": backend.model,
               "questions": {qid: questions[qid] for qid in qids}}
        try:
            async with self._semaphores[backend_name]:
                result = await self.client.ask(backend, sub)
            self.breaker.success(backend_name)
            elapsed = round((time.perf_counter() - started) * 1000)
            return backend_name, qids, result, None, elapsed
        except BackendError as exc:
            message = str(exc); self.breaker.failure(backend_name, message)
            elapsed = round((time.perf_counter() - started) * 1000)
            return backend_name, qids, None, message, elapsed

    async def _shadow_compare(self, routes: list[QuestionRoute], payload: Mapping[str, Any], questions: Mapping[str, Any],
                              answers: Mapping[str, Any], provenance: Mapping[str, str],
                              decision_meta: Mapping[str, Mapping[str, Any]]) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        grouped: dict[str, list[str]] = defaultdict(list)
        route_by_id = {r.question_id: r for r in routes}
        for r in routes:
            if r.shadow_backend and r.question_id in answers:
                grouped[r.shadow_backend].append(r.question_id)
        if not grouped:
            return [], []
        batch_results = await asyncio.gather(*[self._ask_group(name, qids, payload, questions) for name,qids in grouped.items()])
        rows: list[dict[str, Any]]=[]; attempts=[]
        for backend_name,qids,result,error,elapsed in batch_results:
            attempts.append({'backend':backend_name,'questions':list(qids),'latency_ms':elapsed,'status':'failed' if error else 'ok','error':error})
            if error or not isinstance(result,Mapping) or not isinstance(result.get('answers'),Mapping):
                continue
            for qid in qids:
                raw=result['answers'].get(qid)
                if not isinstance(raw,Mapping): continue
                try: clean=validate_answer(questions[qid],raw)
                except AnswerValidationError: continue
                route=route_by_id[qid]; prod=answers[qid]
                prod_key=answer_key(questions[qid],prod); shadow_key=answer_key(questions[qid],clean)
                shadow_score=answer_concentration(clean)
                shadow_drift = (self.drift.observe(route.signature, score=shadow_score, answer_key=shadow_key)
                                if route.registered and backend_name == route.candidate_backend else self.drift.details(route.signature))
                rows.append({
                    'question_id':qid,'signature':route.signature,'deployment_stage':route.deployment_stage,
                    'candidate_backend':route.candidate_backend,'baseline_backend':route.baseline_backend,
                    'production_backend':provenance[qid],'shadow_backend':backend_name,
                    'production_key':prod_key,'shadow_key':shadow_key,
                    'production_score':decision_meta[qid].get('score'),'shadow_score':shadow_score,
                    'agreement':prod_key==shadow_key,'candidate_drift':shadow_drift,
                })
        return rows,attempts

    async def evaluate_detailed(self, payload: Mapping[str, Any], *, request_id: str | None = None) -> tuple[dict[str, Any], dict[str, Any]]:
        questions = payload.get("questions")
        if not isinstance(questions, Mapping) or not questions:
            raise ValueError("questions must be a non-empty object")
        routes = self.plan(questions, request_id=request_id)
        route_by_id = {r.question_id: r for r in routes}
        answers: dict[str, Any] = {}; provenance: dict[str, str] = {}; decision_meta: dict[str, dict[str, Any]] = {}
        in_tokens = out_tokens = 0; errors: dict[str, list[str]] = defaultdict(list); attempts: list[dict[str, Any]] = []
        provisional: dict[str, tuple[dict[str, Any], str, dict[str, Any]]] = {}
        chains = {route.question_id: self._fallback_chain(route) for route in routes}
        cursor = {route.question_id: 0 for route in routes}; pending = {route.question_id for route in routes}

        while pending:
            grouped: dict[str, list[str]] = defaultdict(list); exhausted=[]
            for qid in sorted(pending):
                chain=chains[qid]; idx=cursor[qid]
                if idx>=len(chain): exhausted.append(qid)
                else: grouped[chain[idx]].append(qid)
            if exhausted:
                unresolved=[]
                for qid in exhausted:
                    prior=provisional.pop(qid,None)
                    if prior is None:
                        unresolved.append(qid); continue
                    clean,backend_name,meta=prior
                    answers[qid]=clean; provenance[qid]=backend_name; decision_meta[qid]=meta; pending.discard(qid)
                if unresolved:
                    qid=unresolved[0]; joined=" | ".join(errors[qid]) or "no backend candidates"
                    raise BackendError(f"all backends failed for {qid}: {joined}")
                if not pending:
                    break
            batch_results=await asyncio.gather(*[self._ask_group(name,qids,payload,questions) for name,qids in grouped.items()])
            for backend_name,qids,result,group_error,elapsed_ms in batch_results:
                backend=self.backends[backend_name]; attempt={"backend":backend_name,"questions":list(qids),"latency_ms":elapsed_ms}
                if group_error is not None:
                    attempt.update({"status":"failed","error":group_error[:500]}); attempts.append(attempt)
                    for qid in qids: errors[qid].append(f"{backend_name}: {group_error}"); cursor[qid]+=1
                    continue
                assert result is not None; attempt["status"]="ok"; attempts.append(attempt)
                a,b=self._usage(result); in_tokens+=a; out_tokens+=b
                result_answers=result.get("answers",{})
                if not isinstance(result_answers,Mapping):
                    self.breaker.failure(backend_name,"invalid answers object")
                    for qid in qids: errors[qid].append(f"{backend_name} returned invalid answers object"); cursor[qid]+=1
                    continue
                for qid in qids:
                    answer=result_answers.get(qid)
                    if not isinstance(answer,Mapping): errors[qid].append(f"{backend_name} omitted answer {qid}"); cursor[qid]+=1; continue
                    try: clean=validate_answer(questions[qid],answer)
                    except AnswerValidationError as exc: errors[qid].append(f"{backend_name} invalid answer: {exc}"); cursor[qid]+=1; continue
                    score=answer_concentration(clean); route=route_by_id[qid]
                    # Specialist threshold applies only when the specialist candidate produced the answer.
                    binding_floor=(route.binding.min_score if route.binding and backend_name==route.candidate_backend and route.binding.min_score is not None else 0.0)
                    floor=max(backend.min_concentration,float(binding_floor))
                    if score<floor: errors[qid].append(f"{backend.name} answer score {score:.4f} below required minimum {floor:.4f}"); cursor[qid]+=1; continue
                    drift_info=(self.drift.observe(route.signature,score=score,answer_key=answer_key(questions[qid],clean))
                                if route.registered and backend_name==route.candidate_backend else self.drift.details(route.signature))
                    attestation_verified=False; attestation_checks={}
                    if (route.binding and route.deployment_stage=="stable" and backend_name==route.candidate_backend and
                            route.binding.fallback_policy=="fail_closed"):
                        # If this very observation crosses a drift threshold, authority is denied immediately.
                        route_for_auth=QuestionRoute(**{**vars(route),'drift_status':str(drift_info.get('status','normal'))})
                        attestation_verified,attestation_checks=await self._authority_attestation(route_for_auth,backend_name)
                    meta={
                        "backend":backend_name,"registered":route.registered,"task_id":route.task_id,"signature":route.signature,
                        "score":score,"score_semantics":backend.score_semantics,"authority":bool(attestation_verified),
                        "attestation_verified":attestation_verified,"attestation_checks":attestation_checks,
                        "deployment_stage":route.deployment_stage,"canary_selected":route.canary_selected,
                        "candidate_backend":route.candidate_backend,"baseline_backend":route.baseline_backend,
                        "drift":drift_info,
                        "binding":{
                            "artifact_digest":route.binding.artifact_digest if route.binding else None,
                            "backend_fingerprint":route.binding.backend_fingerprint if route.binding else None,
                            "calibration_digest":route.binding.calibration_digest if route.binding else None,
                            "qualification_digest":route.binding.qualification_digest if route.binding else None,
                            "independent_qualification_digest":route.binding.independent_qualification_digest if route.binding else None,
                            "artifact_attestation_digest":route.binding.artifact_attestation_digest if route.binding else None,
                            "promotion_id":route.binding.promotion_id if route.binding else None,
                            "fallback_policy":route.binding.fallback_policy if route.binding else None,
                        },
                    }
                    chain=chains[qid]; next_name=chain[cursor[qid]+1] if cursor[qid]+1 < len(chain) else None
                    if (not attestation_verified and next_name and self.escalation.should_escalate(
                            score=score, score_semantics=backend.score_semantics, current_backend=backend_name,
                            next_backend=next_name, question_type=route.question_type, capabilities=self.capabilities)):
                        provisional[qid]=(clean,backend_name,meta)
                        attempt.setdefault("escalated_questions",[]).append(qid); attempt["status"]="escalated"
                        errors[qid].append(f"{backend_name}: cost-aware escalation to {next_name}")
                        cursor[qid]+=1; continue
                    answers[qid]=clean; provenance[qid]=backend_name; decision_meta[qid]=meta
                    pending.discard(qid)

        shadow_rows,shadow_attempts=await self._shadow_compare(routes,payload,questions,answers,provenance,decision_meta)
        direct_authorized=bool(decision_meta) and all(x.get("authority") is True for x in decision_meta.values())
        request_envelope={"model":self.config.model,"state":payload.get("state"),"questions":questions}
        request_sha256=hashlib.sha256(canonical_json(request_envelope).encode()).hexdigest()
        plan_value=[{"question_id":r.question_id,"signature":r.signature,"preferred":r.preferred,"fallback_chain":list(chains[r.question_id]),
                     "task_id":r.task_id,"deployment_stage":r.deployment_stage,"shadow_backend":r.shadow_backend,"canary_selected":r.canary_selected} for r in routes]
        plan_sha256=hashlib.sha256(canonical_json(plan_value).encode()).hexdigest()
        evidence_value={"registry_sha256":self.registry.digest,"registry_revision":self.registry.revision,"request_sha256":request_sha256,
                        "plan_sha256":plan_sha256,"direct_authorized":direct_authorized,"decisions":decision_meta}
        evidence_sha256=hashlib.sha256(canonical_json(evidence_value).encode()).hexdigest()
        fabric_meta={"version":5,"authority_version":4,"request_id":request_id,"request_sha256":request_sha256,"plan_sha256":plan_sha256,
                     "evidence_sha256":evidence_sha256,"registry_sha256":self.registry.digest,"registry_revision":self.registry.revision,
                     "registry_integrity_verified":self.registry.integrity_verified,"direct_authorized":direct_authorized,"decisions":decision_meta,
                     "shadow_comparisons":shadow_rows}
        result={"model":str(payload.get("model") or self.config.model),"answers":answers,"usage":{"input_tokens":in_tokens,"output_tokens":out_tokens}}
        if self.config.include_provenance: result["fabric"]=fabric_meta
        trace={"request_id":request_id,"provenance":provenance,"decisions":decision_meta,"attempts":attempts,"shadow_attempts":shadow_attempts,
               "shadow":shadow_rows,"direct_authorized":direct_authorized,"request_sha256":request_sha256,"plan_sha256":plan_sha256,"evidence_sha256":evidence_sha256}
        return result,trace

    async def evaluate(self, payload: Mapping[str, Any]) -> tuple[dict[str, Any], dict[str, str]]:
        result,trace=await self.evaluate_detailed(payload)
        return result,dict(trace["provenance"])

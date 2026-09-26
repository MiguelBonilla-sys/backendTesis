"""Local diagnostic reproductions. No external I/O; all service writes mocked."""
import asyncio
import hashlib
import json
import sys
import time
from collections import Counter
from pathlib import Path
from unittest.mock import AsyncMock, patch

import httpx

from main import app
from auth.jwt import create_refresh_token
from core.config import settings
from core.calibration import choose_theta, reset_effective_theta, set_effective_theta
from agents.fusion_agent import FusionAgent
from schemas.analyze import IDNResult, TIResult, WebProbeResult
from utils.email_parser import parse_eml
from data_pipeline.knowledge_updater import is_usb_baseline_candidate
from data_pipeline.threat_intel import ThreatIntelService
from scripts.eval_baseline_vs_pipeline import _binary_metrics

async def reproduce():
    evidence = {}
    # JWT and CORS: ASGI client does not simulate browser cookie policy.
    token = create_refresh_token({'sub': 'review@example.test', 'role': 'admin'})
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url='https://backend.example.test') as client:
        response = await client.get('/api/v1/auth/me', headers={'Authorization': 'Bearer ' + token})
        evidence['refresh_as_access'] = {'status': response.status_code, 'role': response.json().get('role')}
        origin = 'https://review-untrusted.vercel.app'
        with patch.object(settings, 'APP_ENV', 'production'):
            response = await client.post('/api/v1/auth/refresh', headers={'Origin': origin, 'Cookie': 'refresh_token=' + token})
        evidence['credentialed_cors'] = {'status': response.status_code, 'allow_origin': response.headers.get('access-control-allow-origin'), 'allow_credentials': response.headers.get('access-control-allow-credentials'), 'returns_tokens': bool(response.json().get('access_token'))}
        response = await client.post('/api/v1/auth/refresh', json={'refresh_token': token})
        evidence['old_refresh_reuse'] = {'status_after_prior_refresh': response.status_code}
        limiter = AsyncMock()
        ingest = AsyncMock()
        eml = b'From: Review <review@example.test>\r\nTo: test@example.test\r\nSubject: Notice\r\n\r\nhttps://example.test/link\r\n'
        with patch('routers.eml_router.check_rate_limit', limiter), patch('routers.eml_router._analyze_single_url_for_email', AsyncMock(side_effect=RuntimeError('synthetic upstream failure'))), patch('routers.eml_router.knowledge_updater.ingest_legit_baseline', ingest):
            response = await client.post('/api/v1/analyze_eml', files={'file': ('review.eml', eml, 'message/rfc822')}, headers={'Authorization': 'Bearer ' + token})
        body=response.json()
        evidence['eml_all_urls_failed'] = {'status': response.status_code, 'verdict': body.get('email_verdict'), 'risk': body.get('email_s_risk'), 'url_analyses': len(body.get('url_analyses', []))}
        eml = b'From: "registro@usbbog.edu.co" <attacker@evil.invalid>\r\nTo: test@example.test\r\nSubject: Notice\r\nAuthentication-Results: arbitrary.invalid; spf=pass smtp.mailfrom=evil.invalid; dkim=pass header.d=evil.invalid\r\n\r\nPlain message.\r\n'
        parsed=parse_eml(eml)
        with patch('routers.eml_router.check_rate_limit', limiter), patch('routers.eml_router.knowledge_updater.ingest_legit_baseline', ingest):
            response = await client.post('/api/v1/analyze_eml', files={'file': ('review.eml', eml, 'message/rfc822')}, headers={'Authorization': 'Bearer ' + token})
            await asyncio.sleep(0)
        evidence['baseline_untrusted_headers'] = {'sender_domain': parsed.sender_domain, 'spf_pass': parsed.spf_pass, 'dkim_pass': parsed.dkim_pass, 'status': response.status_code, 'ingestion_called': ingest.await_count > 0}
        evidence['health_routes'] = {'health': (await client.get('/health')).status_code, 'api_v1_health': (await client.get('/api/v1/health')).status_code}
    # Cache: distinct URLs receive controlled GSB outcomes, no HTTP provider.
    service=ThreatIntelService()
    async def cache_case(first_url, first_host, second_url, second_host):
        cache={}
        async def get_cache(key): return cache.get(key)
        async def set_cache(key, value, **kwargs): cache[key]=value
        gsb=AsyncMock(side_effect=[0.0, 1.0])
        with patch('data_pipeline.threat_intel.get_ti_cache', get_cache), patch('data_pipeline.threat_intel.set_ti_cache', set_cache), patch.object(settings,'GOOGLE_SAFE_BROWSING_API_KEY','review-dummy-key'), patch.object(service,'_query_virustotal',AsyncMock(return_value=0.0)), patch.object(service,'_query_urlscan',AsyncMock(return_value=0.0)), patch.object(service,'_query_gsb',gsb), patch.object(service,'_query_whoisxml',AsyncMock(return_value=(0.0,365))):
            await service.analyze(first_url,first_host)
            result=await service.analyze(second_url,second_host)
        return {'second_s_gsb': result.s_gsb, 'provider_calls': gsb.await_count, 'cache_keys': list(cache)}
    evidence['ti_cache_paths']=await cache_case('https://example.test/clean','example.test','https://example.test/phish','example.test')
    evidence['ti_cache_tenants']=await cache_case('https://safe.vercel.app/','safe.vercel.app','https://evil.vercel.app/','evil.vercel.app')
    # Fusion is pure under default weights; no model execution.
    fusion=FusionAgent()
    kwargs=dict(url='https://example.test/',domain='example.test',idn_result=IDNResult(domain_unicode='example.test',confusable_chars=[],homograph_ratio=0,visual_similarity=0,s_idn_local=0,is_mixed_script=False,is_suspicious=False),ti_result=TIResult(s_vt=0,s_urlscan=0,s_gsb=0,s_ti=0),s_llm=.5,llm_reason='review neutral fallback',start_time=time.perf_counter(),s_hf=.5)
    reset_effective_theta()
    with patch.object(settings,'ONLINE_CALIBRATION_ENABLED',False):
        before=await fusion.fuse(**kwargs)
        probe=await fusion.fuse(**kwargs,probe_result=WebProbeResult(s_probe=.6,has_login_form=True,external_form_action=True,brand_impersonation='example-brand'))
        recal=choose_theta([(.22,True)]*15+[(.1,False)]*15)
        set_effective_theta(recal.new_theta)
        after=await fusion.fuse(**kwargs)
    reset_effective_theta()
    evidence['calibration_neutral_floor']={'new_theta':recal.new_theta,'loss':recal.loss,'before':before.verdict,'after':after.verdict,'risk':after.s_risk}
    evidence['probe_gate']={'raw_probe':.6,'effective_probe':probe.agent_scores.s_probe,'risk':probe.s_risk,'verdict':probe.verdict}
    # Existing report only, no corpus requests.
    report_path=Path('reports/baseline_vs_pipeline_20260915_002802.json')
    rows=json.loads(report_path.read_text())['raw_results']
    evidence['existing_evaluation']={'path':str(report_path),'sha256':hashlib.sha256(report_path.read_bytes()).hexdigest(),'rows':len(rows),'unique_urls':len({r['url'] for r in rows}),'hf_exact_neutral':sum(r['s_hf']==.5 for r in rows),'fp_at_exact_neutral':sum(r['s_hf']==.5 and r['expected']=='LEGITIMATE' for r in rows),'baseline':_binary_metrics([(r['s_hf']>=.5,r['expected']=='PHISHING') for r in rows]),'pipeline_at_theta_030':_binary_metrics([(r['s_risk']>=.3,r['expected']=='PHISHING') for r in rows]),'case_fields':list(rows[0])}
    from scripts.sync_pg_bilateral import _merge_uuid_table
    from scripts.sync_chroma_standby import _sync_collection
    local_col, standby_col = AsyncMock(), AsyncMock()
    local, standby = AsyncMock(), AsyncMock()
    local.get_collection.return_value = local_col
    local.get_or_create_collection.return_value = local_col
    standby.get_collection.return_value = standby_col
    standby.get_or_create_collection.return_value = standby_col
    docs = {
        id(local_col): {'ids': [], 'documents': [], 'metadatas': [], 'embeddings': []},
        id(standby_col): {'ids': ['email_deleted_incident'], 'documents': ['old classification'], 'metadatas': [{'source': 'auto_ingest'}], 'embeddings': [[1., 0.]]},
    }
    async def get_all(col, include):
        return docs[id(col)]
    with patch('scripts.sync_chroma_standby._get_all', get_all):
        forward = await _sync_collection('email_embeddings', local, standby, batch=128, prune=False, dest_embed=lambda documents: [[1., 0.] for _ in documents])
        reverse = await _sync_collection('email_embeddings', standby, local, batch=128, prune=False, dest_embed=lambda documents: [[1., 0.] for _ in documents])
    evidence['chroma_deleted_document_resurrection'] = {'forward_upserts': forward[0], 'reverse_upserts': reverse[0], 'restored_id': local_col.upsert.call_args.kwargs['ids'][0]}
    src, dst = AsyncMock(), AsyncMock()
    src.fetch.return_value = [{'id': 'same-user-id'}]
    dst.fetch.return_value = [{'id': 'same-user-id'}]
    moved = await _merge_uuid_table(src, dst, 'users', dry=False)
    evidence['postgres_same_id_update'] = {'rows_considered': moved, 'writes': dst.executemany.await_count}
    return evidence

if __name__=='__main__':
    result=asyncio.run(reproduce())
    if len(sys.argv)>1:
        Path(sys.argv[1]).write_text(json.dumps(result,indent=2,ensure_ascii=False)+'\n')
    print(json.dumps(result,indent=2,ensure_ascii=False))

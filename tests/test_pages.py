"""页面渲染冒烟测试（前端重构 issue #24）— 每页200 + 关键元素 + 设计系统资源"""
from __future__ import annotations

from httpx import ASGITransport, AsyncClient

from aicso.api.app import app

PAGE_CASES = [
    ("/", ["仪表盘", "Case 总数", "severity-chart", "Case 严重度分布"]),
    ("/cases", ["Case 管理", "新建 Case"]),
    ("/cases/new", ["新建 Case", "title", "severity"]),
    ("/alerts", ["告警", "Alert ID"]),
    ("/agents", ["Agent", "triage", "启动调查"]),
    ("/router", ["分流路由", "候选索引", "最近路由决策"]),
    ("/datasources", ["数据源"]),
    ("/mock", ["Mock 注入", "生成参数", "攻击类型"]),
]

STATIC_ASSETS = [
    "/static/css/app.css",
    "/static/js/app.js",
    "/static/vendor/chart.umd.min.js",
]


async def seed_detail_targets() -> tuple[str, str]:
    """注入一条走完整流水线的告警，拿 case/alert id 供详情页断言"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            r = await client.post("/mock/api/generate", json={
                "count": 2, "categories": ["brute_force"], "inject": True})
            assert r.status_code == 200
            cases = (await client.get("/cases/api/list")).json()
            case_id = cases["cases"][0]["case_id"]
            alert_list = (await client.get("/alerts/api/list")).json()
            if isinstance(alert_list, dict):
                alert_list = alert_list.get("alerts", [])
            alert_id = alert_list[0]["alert_id"]
            return case_id, alert_id


async def test_all_pages_render_with_design_system():
    case_id, alert_id = await seed_detail_targets()
    pages = PAGE_CASES + [
        (f"/cases/{case_id}", [case_id, "时间线", "关联告警", "更新状态"]),
        (f"/alerts/{alert_id}", [alert_id, "告警信息"]),
    ]

    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            # 静态资源可用且含设计令牌
            for asset in STATIC_ASSETS:
                r = await client.get(asset)
                assert r.status_code == 200, f"静态资源 {asset} 不可用"
            css = (await client.get("/static/css/app.css")).text
            assert "--c-primary" in css, "设计令牌缺失"

            # 页面渲染
            for path, markers in pages:
                r = await client.get(path)
                assert r.status_code == 200, f"{path} 状态码 {r.status_code}"
                body = r.text
                assert 'href="/static/css/app.css"' in body, f"{path} 未引用设计系统CSS"
                for marker in markers:
                    assert marker in body, f"{path} 缺少关键元素: {marker}"
                # 行内<style>应已移除（样式由外链CSS承载）
                assert "<style>" not in body, f"{path} 仍存在行内样式块"


async def test_case_ops_and_context_api_still_work():
    """前端依赖的JSON API不回归"""
    case_id, _ = await seed_detail_targets()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            r = await client.post(f"/cases/api/{case_id}/ops", json={
                "actor": "tester", "action": "manual_handle", "summary": "smoke"})
            assert r.status_code == 200 and r.json().get("ok") is True
            r = await client.get(f"/cases/api/{case_id}/context")
            assert r.status_code == 200
            ctx = r.json()
            assert ctx["entities"] and len(ctx["ops_records"]) == 1
            assert "ops_executed" in [e["event_type"] for e in ctx["timeline"]]


async def test_update_form_invalid_transition_redirects_not_500():
    """GUI走查发现的bug回归：非法状态转换应303+错误提示，而非500"""
    case_id, _ = await seed_detail_targets()
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            # new → investigating 非法（必须先 assigned）
            r = await client.post(f"/cases/{case_id}/update", data={
                "status": "investigating", "assignee": "", "resolution": ""})
            assert r.status_code == 303, f"应303重定向，实际{r.status_code}"
            assert f"/cases/{case_id}?error=" in r.headers["location"]

            # 详情页带error参数渲染错误banner
            r2 = await client.get(r.headers["location"])
            assert r2.status_code == 200
            assert "banner danger" in r2.text

            # 下拉只渲染合法转换目标（new→只有assigned）
            assert 'value="assigned"' in r2.text
            assert 'value="investigating"' not in r2.text.split("</select>")[0]


async def test_mock_generate_filters_invalid_categories():
    """GUI走查发现的bug回归：非法攻击类别应过滤而非500"""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        async with app.router.lifespan_context(app):
            r = await client.post("/mock/generate", data={
                "count": "3", "inject": "true",
                "categories": "hacking_the_planet",  # 非法类别
            })
            assert r.status_code == 200, f"非法类别应被过滤，实际{r.status_code}"

            # 合法+非法混合：只按合法类别生成
            r2 = await client.post("/mock/generate", data={
                "count": "3", "inject": "true",
                "categories": "brute_force,brute_force",  # 逗号连体（浏览器异常编码）
            })
            assert r2.status_code == 200

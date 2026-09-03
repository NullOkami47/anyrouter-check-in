from __future__ import annotations

import asyncio
import os
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import quote

import httpx


def parse_user_info_response(response: httpx.Response) -> dict[str, Any]:
	if response.status_code == 200:
		try:
			data = response.json()
		except (ValueError, TypeError):
			content_type = response.headers.get('content-type', '').split(';', 1)[0].strip() or 'unknown'
			return {
				'success': False,
				'retryable_waf': True,
				'error': (
					'Failed to get user info: non-JSON HTTP 200 '
					f'(content-type={content_type}; possible WAF challenge)'
				),
			}

		if data.get('success'):
			user_data = data.get('data', {})
			quota = round(user_data.get('quota', 0) / 500000, 2)
			used_quota = round(user_data.get('used_quota', 0) / 500000, 2)
			return {
				'success': True,
				'quota': quota,
				'used_quota': used_quota,
				'display': f':money: Current balance: ${quota}, Used: ${used_quota}',
			}
		return {'success': False, 'error': 'Failed to get user info: API returned success=false'}

	retryable = response.status_code in {403, 408, 425, 429, 500, 502, 503, 504}
	result: dict[str, Any] = {
		'success': False,
		'error': f'Failed to get user info: HTTP {response.status_code}',
	}
	if retryable:
		result['retryable_waf'] = True
	return result


def robust_get_user_info(client, headers, user_info_url: str):
	try:
		response = client.get(user_info_url, headers=headers, timeout=30)
		return parse_user_info_response(response)
	except Exception as exc:
		return {'success': False, 'error': f'Failed to get user info: {str(exc)[:80]}'}


def choose_next_proxy(current: str, all_nodes: list[str], auto_group: str) -> str | None:
	candidates = [name for name in all_nodes if name not in {auto_group, 'DIRECT', 'REJECT'}]
	if not candidates:
		return None
	if current not in candidates:
		return candidates[0]
	index = candidates.index(current)
	return candidates[(index + 1) % len(candidates)]


async def _controller_get(group: str) -> dict[str, Any] | None:
	control_url = os.getenv('CHECKIN_PROXY_CONTROL_URL', '').rstrip('/')
	if not control_url:
		return None
	url = f"{control_url}/proxies/{quote(group, safe='')}"
	async with httpx.AsyncClient(timeout=10) as client:
		response = await client.get(url)
		if response.status_code != 200:
			return None
		payload = response.json()
		return payload if isinstance(payload, dict) else None


async def _controller_select(group: str, node: str) -> bool:
	control_url = os.getenv('CHECKIN_PROXY_CONTROL_URL', '').rstrip('/')
	if not control_url:
		return False
	url = f"{control_url}/proxies/{quote(group, safe='')}"
	async with httpx.AsyncClient(timeout=10) as client:
		response = await client.put(url, json={'name': node})
		return response.status_code in {200, 204}


async def lock_proxy_to_auto_choice() -> bool:
	group = os.getenv('CHECKIN_PROXY_GROUP', 'CHECKIN')
	auto_group = os.getenv('CHECKIN_PROXY_AUTO_GROUP', 'CHECKIN-AUTO')
	auto_state = await _controller_get(auto_group)
	if not auto_state:
		return False
	selected = str(auto_state.get('now') or '').strip()
	if not selected or selected == auto_group:
		return False
	locked = await _controller_select(group, selected)
	if locked:
		print('[INFO] AgentRouter proxy node locked for browser/API consistency')
	return locked


async def rotate_proxy() -> bool:
	group = os.getenv('CHECKIN_PROXY_GROUP', 'CHECKIN')
	auto_group = os.getenv('CHECKIN_PROXY_AUTO_GROUP', 'CHECKIN-AUTO')
	state = await _controller_get(group)
	if not state:
		return False
	current = str(state.get('now') or '')
	all_nodes = [str(item) for item in state.get('all', []) if item]
	selected = choose_next_proxy(current, all_nodes, auto_group)
	if not selected or selected == current:
		return False
	changed = await _controller_select(group, selected)
	if changed:
		print('[INFO] AgentRouter proxy node rotated after retryable WAF response')
	return changed


def is_retryable_check_result(result: tuple[bool, dict | None, dict | None]) -> bool:
	success, before, after = result
	if success:
		return False
	return any(info and info.get('retryable_waf') for info in (before, after))


async def run_with_retries(
	run_once: Callable[[], Awaitable[tuple[bool, dict | None, dict | None]]],
	rotate_once: Callable[[], Awaitable[bool]],
	*,
	attempts: int = 3,
	retry_delay: float = 2.0,
) -> tuple[bool, dict | None, dict | None]:
	attempts = max(1, attempts)
	last_result: tuple[bool, dict | None, dict | None] = (False, None, None)
	for attempt in range(1, attempts + 1):
		last_result = await run_once()
		if last_result[0] or not is_retryable_check_result(last_result) or attempt == attempts:
			return last_result
		print(f'[WARN] AgentRouter WAF/API response is retryable; retrying ({attempt + 1}/{attempts})')
		await rotate_once()
		if retry_delay > 0:
			await asyncio.sleep(retry_delay)
	return last_result


def run_main() -> None:
	import checkin

	original_check_in_account = checkin.check_in_account
	checkin.get_user_info = robust_get_user_info

	async def reliable_check_in_account(account, account_index: int, app_config):
		if account.provider != 'agentrouter' or account.has_login_credentials():
			return await original_check_in_account(account, account_index, app_config)

		try:
			await lock_proxy_to_auto_choice()
		except Exception as exc:
			print(f'[WARN] AgentRouter proxy lock failed: {str(exc)[:120]}')

		attempts = max(1, int(os.getenv('AGENTROUTER_WAF_MAX_ATTEMPTS', '3')))
		retry_delay = max(0.0, float(os.getenv('AGENTROUTER_WAF_RETRY_DELAY_SECONDS', '2')))

		async def run_once():
			return await original_check_in_account(account, account_index, app_config)

		async def rotate_once():
			try:
				return await rotate_proxy()
			except Exception as exc:
				print(f'[WARN] AgentRouter proxy rotation failed: {str(exc)[:120]}')
				return False

		return await run_with_retries(
			run_once,
			rotate_once,
			attempts=attempts,
			retry_delay=retry_delay,
		)

	checkin.check_in_account = reliable_check_in_account
	checkin.run_main()


if __name__ == '__main__':
	run_main()

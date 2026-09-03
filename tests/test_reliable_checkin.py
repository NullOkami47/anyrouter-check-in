import httpx
import pytest

from reliable_checkin import (
	choose_next_proxy,
	is_retryable_check_result,
	parse_user_info_response,
	run_with_retries,
)


def test_http_200_html_is_retryable_waf_response():
	response = httpx.Response(
		200,
		text='<html><title>Access verification</title></html>',
		headers={'content-type': 'text/html; charset=utf-8'},
		request=httpx.Request('GET', 'https://agentrouter.org/api/user/self'),
	)

	result = parse_user_info_response(response)

	assert result['success'] is False
	assert result['retryable_waf'] is True
	assert 'non-JSON HTTP 200' in result['error']
	assert 'possible WAF challenge' in result['error']


def test_valid_json_user_info_keeps_existing_balance_conversion():
	response = httpx.Response(
		200,
		json={
			'success': True,
			'data': {
				'quota': 12_290_000,
				'used_quota': 87_710_000,
			},
		},
		request=httpx.Request('GET', 'https://agentrouter.org/api/user/self'),
	)

	result = parse_user_info_response(response)

	assert result['success'] is True
	assert result['quota'] == 24.58
	assert result['used_quota'] == 175.42


def test_choose_next_proxy_skips_auto_group_and_special_nodes():
	all_nodes = ['CHECKIN-AUTO', 'DIRECT', 'node-a', 'node-b', 'REJECT']

	assert choose_next_proxy('node-a', all_nodes, 'CHECKIN-AUTO') == 'node-b'
	assert choose_next_proxy('CHECKIN-AUTO', all_nodes, 'CHECKIN-AUTO') == 'node-a'


def test_retryable_check_result_requires_failed_waf_marker():
	assert is_retryable_check_result((False, {'success': False, 'retryable_waf': True}, None)) is True
	assert is_retryable_check_result((False, {'success': False, 'error': 'HTTP 401'}, None)) is False
	assert is_retryable_check_result((True, {'success': True}, {'success': True})) is False


@pytest.mark.asyncio
async def test_retryable_waf_rotates_once_then_stops_on_success():
	events = []
	results = iter(
		[
			(False, {'success': False, 'retryable_waf': True}, {'success': False, 'retryable_waf': True}),
			(True, {'success': True}, {'success': True}),
		]
	)

	async def run_once():
		events.append('run')
		return next(results)

	async def rotate_once():
		events.append('rotate')
		return True

	result = await run_with_retries(run_once, rotate_once, attempts=3, retry_delay=0)

	assert result[0] is True
	assert events == ['run', 'rotate', 'run']

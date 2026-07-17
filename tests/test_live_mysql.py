from __future__ import annotations

import os

import pytest

from mycli_lite import connect


@pytest.mark.live
def test_live_connection_and_multiple_results() -> None:
    host = os.getenv('MYCLI_LITE_TEST_HOST')
    if not host:
        pytest.skip('MYCLI_LITE_TEST_HOST is not configured')

    port = int(os.getenv('MYCLI_LITE_TEST_PORT', '3306'))
    get_server_public_key = os.getenv('MYCLI_LITE_TEST_GET_SERVER_PUBLIC_KEY') == '1'
    with connect(
        host=host,
        port=port,
        user=os.getenv('MYCLI_LITE_TEST_USER', 'root'),
        password=os.getenv('MYCLI_LITE_TEST_PASSWORD', ''),
        database=os.getenv('MYCLI_LITE_TEST_DATABASE') or None,
        ssl_mode=os.getenv('MYCLI_LITE_TEST_SSL_MODE', 'disabled'),
        ssl_ca=os.getenv('MYCLI_LITE_TEST_SSL_CA') or None,
        get_server_public_key=get_server_public_key,
    ) as connection:
        results = connection.query('SELECT VERSION(), CURRENT_USER(), DATABASE(); SELECT 1;')

    assert len(results) == 2
    assert results[0].has_rows
    assert len(results[0].rows[0]) == 3
    assert results[1].rows == [('1',)]

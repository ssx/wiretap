<?php

declare(strict_types=1);

use Ssx\Wiretap\CapturedBody;
use Ssx\Wiretap\Exchange;
use Ssx\Wiretap\Headers;
use Ssx\Wiretap\Timings;

/**
 * Build an exchange with sensible defaults, overriding only what a test
 * actually cares about.
 */
function exchange(
    string $uri = 'https://api.example.com/v1/orders',
    string $method = 'POST',
    ?Headers $requestHeaders = null,
    ?CapturedBody $requestBody = null,
    ?int $status = 200,
    ?Headers $responseHeaders = null,
    ?CapturedBody $responseBody = null,
    string $correlationId = 'test-correlation',
    ?Timings $timings = null,
    ?\Ssx\Wiretap\TransferError $error = null,
): Exchange {
    return new Exchange(
        id: 'test-exchange',
        correlationId: $correlationId,
        transport: Exchange::TRANSPORT_CURL,
        method: $method,
        uri: $uri,
        requestHeaders: $requestHeaders ?? Headers::empty(),
        requestBody: $requestBody ?? CapturedBody::none(),
        status: $status,
        reason: $status === 200 ? 'OK' : null,
        responseHeaders: $responseHeaders ?? Headers::empty(),
        responseBody: $responseBody ?? CapturedBody::none(),
        timings: $timings ?? new Timings(total: 1000),
        error: $error,
        startedAt: 1_758_000_000.0,
    );
}

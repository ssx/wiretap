<?php

declare(strict_types=1);

namespace Ssx\Wiretap\Testing;

/**
 * Thrown when a wiretap assertion fails.
 *
 * A plain exception rather than a PHPUnit one, so the test API works under
 * Pest, PHPUnit, PHPSpec or a hand-rolled runner. Where PHPUnit is present
 * the assertions route through Assert::fail() instead, so a failure counts as
 * a failed assertion rather than an errored test.
 */
final class AssertionFailed extends \RuntimeException
{
}
